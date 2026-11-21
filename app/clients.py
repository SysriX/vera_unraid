"""VERA-Connect: Windows computers that fetch their WireGuard configuration themselves.

Public endpoints (signed by the device key, no login) – the only part of VERA that has to be reachable from outside:
    POST /client/enroll   {machine_id, public_key, hostname, domain, user, os, version, enroll_key}
    POST /client/poll     {config_hash, report{…}}  → {status, config_hash, tunnel, interval, …}
    POST /client/config   → {tunnel, text, hash}     (only for approved computers)

Every request carries
    X-Device:    machine id
    X-Time:      unix time (±300 s)
    X-Nonce:     random hex (no replay within 10 min)
    X-Signature: base64 Ed25519 over "METHOD\\nPATH\\nTIME\\nNONCE\\nsha256hex(body)"
On enroll the key comes in the body (proof of possession); afterwards VERA only accepts the key it pinned.

Admin endpoints under /api/clients (login or API token) – page "Rechner" in the UI.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import os
import time
from datetime import datetime

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import JSON, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

import core
from core import Base, now, session

POLL_PENDING, POLL_APPROVED = 60, 300
TUNNEL_RE = re.compile(r"[^A-Za-z0-9_=+.-]")


# ------------------------------------------------------------------ tables
class Client(Base):
    __tablename__ = "vera_client"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    public_key: Mapped[str] = mapped_column(String(64), default="")         # base64, 32 bytes
    status: Mapped[str] = mapped_column(String(16), default="pending")      # pending | approved | blocked
    note: Mapped[str] = mapped_column(String(255), default="")               # e.g. "Geräteschlüssel geändert"
    hostname: Mapped[str] = mapped_column(String(128), default="")
    domain: Mapped[str] = mapped_column(String(128), default="")
    username: Mapped[str] = mapped_column(String(128), default="")
    os: Mapped[str] = mapped_column(String(128), default="")
    client_version: Mapped[str] = mapped_column(String(32), default="")
    wg_version: Mapped[str] = mapped_column(String(32), default="")
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    peer_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tunnel: Mapped[str] = mapped_column(String(32), default="")
    report: Mapped[dict] = mapped_column(JSON, default=dict)                 # last state report of the client
    config_hash: Mapped[str] = mapped_column(String(64), default="")         # what the client has installed
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[str] = mapped_column(String(64), default="")
    approved_by: Mapped[str] = mapped_column(String(128), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    history: Mapped[list] = mapped_column(JSON, default=list)               # last events (max 30)


class Setting(Base):
    __tablename__ = "vera_setting"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


def setting(key: str, default: str = "") -> str:
    with session() as s:
        x = s.get(Setting, key)
        return x.value if x else default


def set_setting(key: str, value: str) -> None:
    with session() as s:
        x = s.get(Setting, key) or Setting(key=key)
        x.value = value
        s.merge(x)


# ------------------------------------------------------------------ signatures
_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()


def _b64(x: str) -> bytes:
    return base64.b64decode(x + "=" * (-len(x) % 4))


def check_signature(req: Request, body: bytes, public_key_b64: str) -> None:
    h = req.headers
    try:
        ts, nonce, sig = int(h.get("x-time", "0")), h.get("x-nonce", ""), _b64(h.get("x-signature", ""))
    except ValueError as e:
        raise HTTPException(401, "Signatur fehlt") from e
    if abs(time.time() - ts) > 300:
        raise HTTPException(401, "Uhrzeit des Rechners weicht mehr als 5 Minuten ab")
    if not re.fullmatch(r"[0-9a-f]{16,64}", nonce):
        raise HTTPException(401, "Signatur fehlt")
    msg = f"{req.method}\n{req.url.path}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
    try:
        Ed25519PublicKey.from_public_bytes(_b64(public_key_b64)).verify(sig, msg)
    except (InvalidSignature, ValueError) as e:
        raise HTTPException(401, "Signatur ungültig") from e
    with _nonce_lock:
        t = time.time()
        for k in [k for k, v in _nonces.items() if t - v > 600]:
            del _nonces[k]
        key = f"{h.get('x-device', '')}:{nonce}"
        if key in _nonces:
            raise HTTPException(401, "Anfrage wurde schon einmal gesendet")
        _nonces[key] = t


def _hist(c: Client, text: str) -> None:
    c.history = [*(c.history or [])[-29:], {"t": now().isoformat(), "e": text}]


def tunnel_name(fw_site: str) -> str:
    n = TUNNEL_RE.sub("", (fw_site or "VERA").replace(" ", "-"))[:32]
    return n or "VERA"


# ------------------------------------------------------------------ public router (/client/…)
def build_public_router(host) -> APIRouter:
    r = APIRouter()

    async def _client(req: Request) -> tuple[Client, bytes, dict]:
        body = await req.body()
        mid = req.headers.get("x-device", "")
        with session() as s:
            c = s.scalar(select(Client).where(Client.machine_id == mid))
            if not c:
                raise HTTPException(404, "Rechner unbekannt – bitte neu anmelden")
            s.expunge(c)
        check_signature(req, body, c.public_key)
        try:
            data = json.loads(body or b"{}")
        except ValueError as e:
            raise HTTPException(400, "kein JSON") from e
        return c, body, data

    @r.post("/client/enroll")
    async def enroll(req: Request):
        body = await req.body()
        try:
            d = json.loads(body or b"{}")
        except ValueError as e:
            raise HTTPException(400, "kein JSON") from e
        mid = str(d.get("machine_id") or "")
        if not re.fullmatch(r"[0-9a-f]{32,64}", mid) or mid != req.headers.get("x-device"):
            raise HTTPException(400, "Rechner-Kennung fehlt oder ist ungültig")
        pub = str(d.get("public_key") or "")
        check_signature(req, body, pub)                               # proves the client holds the key
        want = setting("enroll_key")
        if want and not secrets.compare_digest(str(d.get("enroll_key") or ""), want):
            raise HTTPException(403, "Anmelde-Schlüssel fehlt oder stimmt nicht")
        ip = req.client.host if req.client else ""
        info = {k: str(d.get(k) or "")[:128] for k in ("hostname", "domain", "user", "os", "version")}
        with session() as s:
            c = s.scalar(select(Client).where(Client.machine_id == mid))
            new = c is None
            if new:
                c = Client(machine_id=mid, public_key=pub, status="pending")
                s.add(c)
                _hist(c, "angemeldet – wartet auf Freigabe")
            elif c.public_key != pub:                                 # cloned disk / reinstalled Windows
                c.public_key = pub
                if c.status == "approved":
                    c.status, c.note = "pending", "Geräteschlüssel geändert – bitte prüfen und neu freigeben"
                _hist(c, "neuer Geräteschlüssel")
            c.hostname, c.domain, c.username, c.os, c.client_version = (info["hostname"], info["domain"], info["user"],
                                                                         info["os"], info["version"])
            c.last_seen, c.last_ip = now(), ip
            status = c.status
        if new:
            core.audit(info["hostname"] or mid[:12], "VERA-Connect: Rechner angemeldet", info["user"], ip=ip)
        return {"status": status, "interval": POLL_PENDING if status != "approved" else POLL_APPROVED}

    @r.post("/client/poll")
    async def poll(req: Request):
        c, _, d = await _client(req)
        rep = d.get("report") or {}
        out = {"status": c.status, "interval": POLL_APPROVED if c.status == "approved" else POLL_PENDING,
               "allow_disconnect": setting("allow_disconnect", "1") == "1"}
        cfg = None
        if c.status == "approved" and c.peer_id and c.firewall_id:
            try:
                cfg = _config(host, c)
                out.update(tunnel=c.tunnel, config_hash=cfg["hash"])
            except Exception as e:  # noqa: BLE001
                out.update(status="no_config", message=str(e)[:300])
        elif c.status == "approved":
            out.update(status="no_config", message="Kein WireGuard-Zugang zugeordnet")
        with session() as s:
            x = s.get(Client, c.id)
            x.last_seen, x.last_ip = now(), req.client.host if req.client else ""
            if rep:
                x.report = {k: rep[k] for k in list(rep)[:30]}
                for k, attr in (("version", "client_version"), ("wg_version", "wg_version"), ("user", "username"),
                                ("hostname", "hostname")):
                    if rep.get(k):
                        setattr(x, attr, str(rep[k])[:128])
            if d.get("config_hash") is not None:
                x.config_hash = str(d.get("config_hash") or "")[:64]
            for ev in (d.get("events") or [])[:10]:
                _hist(x, str(ev)[:200])
        return out

    @r.post("/client/config")
    async def config(req: Request):
        c, _, _ = await _client(req)
        if c.status != "approved":
            raise HTTPException(403, "Rechner ist nicht freigegeben")
        if not (c.peer_id and c.firewall_id):
            raise HTTPException(409, "Kein WireGuard-Zugang zugeordnet")
        cfg = _config(host, c, mark=True)
        with session() as s:
            x = s.get(Client, c.id)
            _hist(x, "Konfiguration abgeholt")
        core.audit(c.hostname or c.machine_id[:12], "VERA-Connect: Konfiguration abgeholt", c.tunnel,
                   ip=req.client.host if req.client else "")
        return {"tunnel": c.tunnel, "text": cfg["text"], "hash": cfg["hash"]}

    return r


def _config(host, c: Client, mark: bool = False) -> dict:
    svc = host.service(c.firewall_id)
    try:
        r = svc.config(c.peer_id, reveal=True, mark_fetched=mark)
    finally:
        svc.close()
    if not r.get("complete"):
        raise RuntimeError("Für den Zugang ist kein privater Schlüssel gespeichert")
    text = r["text"]
    return {"text": text, "hash": hashlib.sha256(text.encode()).hexdigest()}


# ------------------------------------------------------------------ admin router (/api/clients)
def client_dict(c: Client, peers: dict | None = None) -> dict:
    rep = c.report or {}
    return {"id": c.id, "machine_id": c.machine_id, "status": c.status, "note": c.note, "hostname": c.hostname,
            "domain": c.domain, "username": c.username, "os": c.os, "client_version": c.client_version,
            "wg_version": c.wg_version, "firewall_id": c.firewall_id, "peer_id": c.peer_id, "tunnel": c.tunnel,
            "peer_name": (peers or {}).get(c.peer_id, ""), "report": rep, "config_hash": c.config_hash,
            "key_fingerprint": hashlib.sha256(_b64(c.public_key)).hexdigest()[:16] if c.public_key else "",
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None, "last_ip": c.last_ip,
            "approved_by": c.approved_by, "approved_at": c.approved_at.isoformat() if c.approved_at else None,
            "history": list(reversed(c.history or []))}


def build_admin_router(host, store) -> APIRouter:
    from wgcore.models import Peer

    r = APIRouter(prefix="/api/clients")
    read, admin = host.role("read"), host.role("admin")

    def _peers() -> dict:
        with store().session() as db:
            return {p.id: p.name for p in db.scalars(select(Peer))}

    @r.get("")
    def list_clients(u=Depends(read)):
        peers = _peers()
        with session() as s:
            rows = [client_dict(c, peers) for c in s.scalars(select(Client).order_by(Client.status != "pending", Client.hostname))]
        return {"clients": rows, "enroll_key": setting("enroll_key") if u["level"] == "admin" else None,
                "enroll_key_set": bool(setting("enroll_key")), "allow_disconnect": setting("allow_disconnect", "1") == "1"}

    @r.post("/{cid}/approve")
    async def approve(cid: int, req: Request, u=Depends(admin)):
        """mode=new: create a WireGuard peer for this computer (keys generated → config complete);
        mode=existing: use a peer that has a private key stored in VERA."""
        d = await req.json()
        fid = int(d.get("firewall_id") or 0)
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            hostname, user = c.hostname, c.username
        svc = host.service(fid)
        try:
            if d.get("mode") == "existing":
                pid = int(d.get("peer_id") or 0)
                cfg = svc.config(pid, reveal=False)
                if not cfg.get("complete"):
                    raise HTTPException(400, "Für diesen Zugang ist kein privater Schlüssel in VERA – „Neuer Zugang“ wählen oder dort neue Schlüssel erzeugen")
            else:
                iid = int(d.get("instance_id") or 0)
                name = (d.get("name") or hostname or "Rechner").strip()
                peer = svc.create_peer({"instance_id": iid, "name": name, "owner": d.get("owner") or user,
                                        "device": f"VERA-Connect {hostname}".strip(),
                                        "tunnel_address": d.get("tunnel_address") or svc.next_ip(iid),
                                        "description": "angelegt über VERA-Connect"}, u["name"])
                pid = peer["id"]
            tn = tunnel_name(d.get("tunnel") or svc.site_name)
        finally:
            svc.close()
        with session() as s:
            c = s.get(Client, cid)
            c.status, c.note, c.firewall_id, c.peer_id, c.tunnel = "approved", "", fid, pid, tn
            c.approved_by, c.approved_at = u["name"], now()
            _hist(c, f"freigegeben von {u['name']}")
            res = client_dict(c, _peers())
        host.audit(u, "VERA-Connect: Rechner freigegeben", res["hostname"], details=f"Zugang {res['peer_name']} · Tunnel {tn}")
        return res

    @r.post("/{cid}/block")
    def block(cid: int, u=Depends(admin)):
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            c.status = "blocked"
            _hist(c, f"gesperrt von {u['name']}")
            name = c.hostname
        host.audit(u, "VERA-Connect: Rechner gesperrt", name)
        return {"ok": True}

    @r.delete("/{cid}")
    def remove(cid: int, u=Depends(admin)):
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            name = c.hostname
            s.delete(c)
        host.audit(u, "VERA-Connect: Rechner entfernt", name, details="Der WireGuard-Zugang bleibt bestehen")
        return {"ok": True}

    @r.put("/settings")
    async def settings(req: Request, u=Depends(admin)):
        d = await req.json()
        if "enroll_key" in d:
            v = d["enroll_key"]
            set_setting("enroll_key", ("vk_" + secrets.token_urlsafe(18)) if v == "new" else "")
        if "allow_disconnect" in d:
            set_setting("allow_disconnect", "1" if d["allow_disconnect"] else "0")
        host.audit(u, "VERA-Connect: Einstellungen geändert", "", details=json.dumps({k: (v if k != "enroll_key" else "…") for k, v in d.items()}))
        return {"enroll_key": setting("enroll_key"), "allow_disconnect": setting("allow_disconnect", "1") == "1"}

    # ---- installer with built-in settings (VERA address, update server, keys)
    @r.get("/installer/settings")
    def installer_settings(req: Request, u=Depends(admin)):
        return _installer_info(req)

    @r.put("/installer/settings")
    async def installer_settings_set(req: Request, u=Depends(admin)):
        d = await req.json()
        for k in ("vera_url", "update_url", "update_key", "tunnel", "base_url"):
            if k in d:
                set_setting("installer_" + k, (d[k] or "").strip())
        host.audit(u, "VERA-Connect: Installer-Einstellungen geändert", "", details=json.dumps({k: v for k, v in d.items() if k != "update_key"}))
        return _installer_info(req)

    @r.post("/installer/refresh")
    def installer_refresh(req: Request, u=Depends(admin)):
        url = setting("installer_base_url") or BASE_EXE_URL
        try:
            with httpx.Client(timeout=120, follow_redirects=True) as c:
                resp = c.get(url)
            if resp.status_code != 200:
                raise HTTPException(400, f"Download {url}: HTTP {resp.status_code}")
            _store_base(resp.content, f"heruntergeladen von {url}")
        except httpx.HTTPError as e:
            raise HTTPException(400, f"Download fehlgeschlagen: {e}") from e
        host.audit(u, "VERA-Connect: Grund-EXE aktualisiert", url)
        return _installer_info(req)

    @r.put("/installer/base")
    async def installer_base_upload(req: Request, u=Depends(admin)):
        _store_base(await req.body(), f"hochgeladen von {u['name']}")
        host.audit(u, "VERA-Connect: Grund-EXE hochgeladen", "")
        return _installer_info(req)

    @r.get("/installer")
    def installer_download(req: Request, u=Depends(admin)):
        """The base EXE plus a line with the settings at the end – VERA-Connect reads it at setup."""
        from fastapi.responses import Response
        if not os.path.exists(BASE_EXE):
            raise HTTPException(409, "Noch keine Grund-EXE – „Von GitHub laden“ oder eine EXE hochladen")
        info = _installer_info(req)
        cfg = {"url": info["vera_url"], "update_url": info["update_url"], "update_key": info["update_key"],
               "enroll_key": setting("enroll_key"), "tunnel": info["tunnel"]}
        cfg = {k: v for k, v in cfg.items() if v or k == "update_url"}
        if not cfg.get("url"):
            raise HTTPException(400, "Adresse von VERA fehlt")
        data = _strip_config(open(BASE_EXE, "rb").read()) + b"\nVERA-CONNECT-CONFIG:" + json.dumps(cfg).encode() + b"\n"
        name = "VERA-Connect-Setup-" + re.sub(r"[^A-Za-z0-9.-]", "_", cfg["url"].split("//")[-1].split("/")[0]) + ".exe"
        host.audit(u, "VERA-Connect: Installer heruntergeladen", cfg["url"],
                   details=f"Update: {cfg.get('update_url') or '–'}, Anmelde-Schlüssel {'ja' if cfg.get('enroll_key') else 'nein'}")
        return Response(data, media_type="application/vnd.microsoft.portable-executable",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    return r


# ------------------------------------------------------------------ installer helpers
BASE_EXE_URL = "https://github.com/SysriX/vera_unraid/releases/download/connect-windows/VERA-Connect-Setup.exe"
BASE_EXE = os.path.join(core.DATA, "connect", "VERA-Connect-Setup.exe")


def _strip_config(b: bytes) -> bytes:
    i = b.rfind(b"\nVERA-CONNECT-CONFIG:", max(0, len(b) - 65536))
    return b[:i] if i >= 0 else b


def _exe_version(b: bytes) -> str:
    """FileVersion from the version resource of the EXE (UTF-16) – good enough to show which build is used."""
    key = "FileVersion".encode("utf-16-le") + b"\x00\x00"
    i = b.find(key)
    if i < 0:
        return ""
    j = i + len(key)
    while j < len(b) - 1 and b[j:j + 2] == b"\x00\x00":
        j += 2
    k = b.find(b"\x00\x00", j)
    try:
        v = b[j:k + (k - j) % 2].decode("utf-16-le").strip("\x00").strip()
    except UnicodeDecodeError:
        return ""
    return v[:-2] if v.endswith(".0") and v.count(".") == 3 else v


def _store_base(b: bytes, origin: str) -> None:
    if len(b) < 100_000 or not b.startswith(b"MZ"):
        raise HTTPException(400, "Das ist keine Windows-EXE")
    b = _strip_config(b)
    os.makedirs(os.path.dirname(BASE_EXE), exist_ok=True)
    with open(BASE_EXE + ".neu", "wb") as f:
        f.write(b)
    os.replace(BASE_EXE + ".neu", BASE_EXE)
    set_setting("installer_base_info", json.dumps({"origin": origin, "version": _exe_version(b), "size": len(b),
                                                   "time": now().isoformat()}))


def _installer_info(req: Request) -> dict:
    fwd = req.headers.get("x-forwarded-host") or req.headers.get("host") or ""
    proto = req.headers.get("x-forwarded-proto") or req.url.scheme
    try:
        base = json.loads(setting("installer_base_info") or "{}")
    except ValueError:
        base = {}
    return {"vera_url": setting("installer_vera_url"), "suggest_vera_url": f"{proto}://{fwd}" if fwd else "",
            "update_url": setting("installer_update_url"), "update_key": setting("installer_update_key"),
            "tunnel": setting("installer_tunnel"), "base_url": setting("installer_base_url") or BASE_EXE_URL,
            "base": base if os.path.exists(BASE_EXE) else None, "enroll_key_set": bool(setting("enroll_key"))}
