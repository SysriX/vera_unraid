"""VERA-Connect: Windows computers that fetch their WireGuard configuration themselves.

Public endpoints (signed by the device key, no login) – the only part of VERA that has to be reachable from outside:
    POST /client/enroll   {machine_id, public_key, hostname, domain, user, os, version, enroll_key}
    POST /client/poll     {config_hash, report{…}}  → {status, config_hash, tunnel, interval, …}
    POST /client/config   → {tunnel, text, hash}     (only for approved computers)
    POST /client/backup/upload  {meta{…}, blob}  → {id}       backup of VERA-Connect (tunnels + settings), sealed on the
    POST /client/backup/list    → {backups[…]}                computer with a passphrase VERA never sees; approved computers
    POST /client/backup/get     {id} → {meta, blob}           only, own backups only (or copied to it by an admin)
    POST /client/backup/delete  {id}

Every request carries
    X-Device:    machine id
    X-Time:      unix time (±300 s)
    X-Nonce:     random hex (no replay within 10 min)
    X-Signature: base64 Ed25519 over "METHOD\\nPATH\\nTIME\\nNONCE\\nsha256hex(body)"
On enroll the key comes in the body (proof of possession); afterwards VERA only accepts the key it pinned.

Device identity ("Geräte-Ausweis", see identitaet/GERAETE-AUSWEIS.md – same scheme as BERTA):
    fingerprint  hardware values (SMBIOS UUID, board/BIOS/disk serial, TPM EK hash, MachineGuid) – which computer,
                 compared with tolerance, never a secret and never a reason to approve on its own
    device key   the pinned Ed25519 key – the proof. A NEW key for a known machine id does not replace the pinned one:
                 it waits as pending_key until an admin takes it over ("Schlüssel übernehmen"); the computer stays
                 approved with its old key meanwhile. An unknown machine id with matching hardware becomes a new waiting
                 entry with a suggestion ("gleiche Hardware wie …") – the admin can move the identity over ("Umtragen").
    credential   record signed by this VERA (key, machine id, fingerprint hash) – issued on approval/takeover, sent in poll
    revoked keys vera_revoked_key – replaced or blocked keys are refused with 403

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
from sqlalchemy import JSON, DateTime, Integer, String, Text, func, select
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
    fingerprint: Mapped[str] = mapped_column(Text, default="")               # JSON of cleaned hardware values
    key_storage: Mapped[str] = mapped_column(String(12), default="")         # dpapi | tpm
    credential: Mapped[str] = mapped_column(Text, default="")                # JSON {credential, signature, signer}
    credential_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pending_key: Mapped[str] = mapped_column(String(64), default="")         # new key of this machine id, waits for takeover
    pending_fp: Mapped[str] = mapped_column(Text, default="")
    pending_storage: Mapped[str] = mapped_column(String(12), default="")
    pending_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suggested_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # waiting entry: same hardware as this computer
    match_quality: Mapped[str] = mapped_column(String(12), default="")        # same | partial


class RevokedKey(Base):
    __tablename__ = "vera_revoked_key"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_key: Mapped[str] = mapped_column(String(64), index=True)
    client_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str] = mapped_column(String(255), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Backup(Base):
    """Backup of VERA-Connect: blob = JSON sealed by the client (PBKDF2 + HMAC-SHA256), meta = readable summary."""
    __tablename__ = "vera_client_backup"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(Integer, index=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    blob: Mapped[str] = mapped_column(Text(length=4_000_000), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    origin: Mapped[str] = mapped_column(String(128), default="")             # "" = from this computer, else "kopiert von …"


BACKUP_MAX = 512_000


def _local(dt) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:                                                     # SQLite returns naive UTC
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%d.%m.%Y %H:%M")


def backup_dict(b: Backup) -> dict:
    return {"id": b.id, "created": b.created.isoformat() if b.created else None, "created_local": _local(b.created),
            "meta": b.meta or {}, "size": b.size, "origin": b.origin}


def backup_keep() -> int:
    try:
        return max(1, min(200, int(setting("backup_keep", "20"))))
    except ValueError:
        return 20


def _prune(s, client_id: int) -> None:
    rows = s.scalars(select(Backup).where(Backup.client_id == client_id).order_by(Backup.created.desc(), Backup.id.desc())).all()
    for b in rows[backup_keep():]:
        s.delete(b)


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


# ------------------------------------------------------------------ device identity (fingerprint, credential, revocation)
STRONG = ("smbios_uuid", "board_serial", "disk_serial", "tpm_ek")
WEAK = ("bios_serial", "machine_guid")
JUNK = {"", "0", "none", "null", "n/a", "na", "default string", "to be filled by o.e.m.", "to be filled by oem", "system serial number",
        "ffffffff-ffff-ffff-ffff-ffffffffffff", "00000000-0000-0000-0000-000000000000", "03000200-0400-0500-0006-000700080009",
        "not applicable", "not specified", "123456789", "chassis serial number", "base board serial number"}
FP_LABELS = {"smbios_uuid": "SMBIOS-UUID", "board_serial": "Mainboard-Seriennummer", "disk_serial": "Seriennummer Systemplatte",
             "tpm_ek": "TPM (EK-Hash)", "bios_serial": "BIOS-Seriennummer", "machine_guid": "Windows-MachineGuid"}


def clean(fp: dict) -> dict:
    out = {}
    for k in STRONG + WEAK:
        v = str((fp or {}).get(k) or "").strip()
        if v.lower() not in JUNK and len(v) >= 4 and len(set(v.replace("-", ""))) > 1:
            out[k] = v.upper()
    return out


def compare(a: dict, b: dict) -> str:
    """same | partial | different (a, b already cleaned)."""
    agree = sum(1 for k in STRONG if k in a and k in b and a[k] == b[k])
    clash = sum(1 for k in STRONG if k in a and k in b and a[k] != b[k])
    weak_agree = sum(1 for k in WEAK if k in a and k in b and a[k] == b[k])
    if agree >= 2 and clash == 0:
        return "same"
    if (agree >= 2 and clash == 1) or (agree == 1 and clash == 0 and weak_agree >= 1):
        return "partial"
    return "different"


def _fp(raw: str) -> dict:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def best_match(s, fp: dict, exclude_id: int | None = None):
    """Known (not waiting) computer with the same hardware → (client, "same"|"partial") or (None, "different")."""
    if not fp:
        return None, "different"
    best, quality = None, "different"
    for c in s.scalars(select(Client).where(Client.status != "pending")):
        if c.id == exclude_id:
            continue
        q = compare(fp, _fp(c.fingerprint))
        if q == "same":
            return c, q
        if q == "partial" and best is None:
            best, quality = c, q
    return best, quality


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


_sign_lock = threading.Lock()
_sign_cache: list = []


def signing_key():
    """Ed25519 key of this VERA that signs the credentials (encrypted with secret.key in vera_setting)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with _sign_lock:
        if _sign_cache:
            return _sign_cache[0]
        enc = setting("id_signing_key")
        raw = base64.b64decode(core.decrypt(enc)) if enc else b""
        if not raw:
            k = Ed25519PrivateKey.generate()
            raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            set_setting("id_signing_key", core.encrypt(base64.b64encode(raw).decode()))
        _sign_cache.append(Ed25519PrivateKey.from_private_bytes(raw))
        return _sign_cache[0]


def signing_public() -> str:
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(signing_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def issue_credential(c) -> str:
    body = {"v": 1, "service": "vera", "issuer": core.instance_id(), "device_id": c.id, "machine_id": c.machine_id,
            "public_key": c.public_key, "fingerprint": hashlib.sha256(_canonical(_fp(c.fingerprint))).hexdigest(),
            "key_storage": c.key_storage or "", "issued": int(time.time())}
    sig = base64.b64encode(signing_key().sign(_canonical(body))).decode()
    c.credential = json.dumps({"credential": body, "signature": sig, "signer": signing_public()})
    c.credential_at = now()
    return c.credential


def revoked(s, public_key: str) -> bool:
    return bool(public_key) and s.scalar(select(RevokedKey.id).where(RevokedKey.public_key == public_key).limit(1)) is not None


def revoke(s, c, reason: str, key: str | None = None) -> None:
    k = key if key is not None else c.public_key
    if k and not revoked(s, k):
        s.add(RevokedKey(public_key=k, client_id=c.id, reason=reason[:255], at=now()))
        s.flush()


def key_fp(k: str) -> str:
    return hashlib.sha256(_b64(k)).hexdigest()[:16] if k else ""


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
        """Signed request of a known computer. With the pinned key: as is. With the waiting new key (pending_key):
        the returned copy has status "pending" – it may poll, nothing else."""
        body = await req.body()
        mid = req.headers.get("x-device", "")
        with session() as s:
            c = s.scalar(select(Client).where(Client.machine_id == mid))
            if not c:
                raise HTTPException(404, "Rechner unbekannt – bitte neu anmelden")
            s.expunge(c)
        try:
            check_signature(req, body, c.public_key)
            used = c.public_key
        except HTTPException:
            if not c.pending_key:
                raise
            check_signature(req, body, c.pending_key)
            used = c.pending_key
            c.status, c.note, c.credential = "pending", "neuer Geräteschlüssel – wartet auf Übernahme in VERA", ""
        with session() as s:
            if revoked(s, used):
                raise HTTPException(403, "Geräteschlüssel dieses Rechners wurde gesperrt – VERA-Connect neu anmelden")
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
        fp = clean(d.get("fingerprint") if isinstance(d.get("fingerprint"), dict) else {})
        storage = re.sub(r"[^a-z0-9]", "", str(d.get("key_storage") or "dpapi").lower())[:12] or "dpapi"
        event, credential = "", ""
        with session() as s:
            if revoked(s, pub):
                raise HTTPException(403, "Dieser Geräteschlüssel wurde gesperrt – VERA-Connect neu installieren")
            c = s.scalar(select(Client).where(Client.machine_id == mid))
            if c is None:
                match, quality = best_match(s, fp)
                c = Client(machine_id=mid, public_key=pub, status="pending", fingerprint=json.dumps(fp), key_storage=storage,
                           suggested_id=match.id if match else None, match_quality=quality if match else "")
                s.add(c)
                like = f"gleiche Hardware wie {match.hostname or match.machine_id[:12]}" if match else ""
                _hist(c, "angemeldet – wartet auf Freigabe" + (f" ({like})" if like else ""))
                event = "VERA-Connect: Rechner angemeldet" + (f" – {like}" if like else "")
                status = "pending"
            elif c.public_key == pub:
                if fp:
                    old = _fp(c.fingerprint)
                    if old and compare(fp, old) == "different":
                        _hist(c, "Hardware-Werte weichen stark ab – bitte prüfen")
                        c.note = "Hardware-Werte weichen vom bekannten Stand ab"
                    else:
                        c.fingerprint = json.dumps(fp)
                c.key_storage = storage
                if c.status == "approved" and not c.credential:
                    issue_credential(c)
                status = c.status
                credential = c.credential if c.status == "approved" else ""
            elif c.status == "pending":                              # never approved: nothing to protect, take the new key
                c.public_key, c.fingerprint, c.key_storage = pub, json.dumps(fp), storage
                _hist(c, "neuer Geräteschlüssel (noch nicht freigegeben)")
                status = "pending"
            else:                                                    # approved/blocked: the pinned key stays, the new one waits
                if c.pending_key != pub:
                    c.pending_key, c.pending_fp, c.pending_storage, c.pending_since = pub, json.dumps(fp), storage, now()
                    _hist(c, "neuer Geräteschlüssel – wartet auf Übernahme")
                    event = "VERA-Connect: neuer Geräteschlüssel wartet"
                status = "pending"
            c.hostname, c.domain, c.username, c.os, c.client_version = (info["hostname"], info["domain"], info["user"],
                                                                         info["os"], info["version"])
            c.last_seen, c.last_ip = now(), ip
        if event:
            core.audit(info["hostname"] or mid[:12], event, info["user"], ip=ip)
        return {"status": status, "interval": POLL_PENDING if status != "approved" else POLL_APPROVED, "credential": credential}

    @r.post("/client/poll")
    async def poll(req: Request):
        c, _, d = await _client(req)
        rep = d.get("report") or {}
        out = {"status": c.status, "interval": POLL_APPROVED if c.status == "approved" else POLL_PENDING,
               "allow_disconnect": setting("allow_disconnect", "1") == "1", "backup": True,
               "credential": c.credential if c.status == "approved" else ""}
        if c.status == "pending" and c.note:
            out["message"] = c.note
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
            fp = clean(d.get("fingerprint") if isinstance(d.get("fingerprint"), dict) else {})
            if fp and c.status == "approved" and x.public_key == c.public_key:
                old = _fp(x.fingerprint)
                if old and compare(fp, old) == "different":
                    if not x.note:
                        _hist(x, "Hardware-Werte weichen stark ab – bitte prüfen")
                    x.note = "Hardware-Werte weichen vom bekannten Stand ab"
                else:
                    x.fingerprint = json.dumps(fp)
            if c.status == "approved" and not x.credential:
                out["credential"] = issue_credential(x)
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

    # ---- backups of VERA-Connect (approved computers only)
    async def _approved(req: Request) -> tuple[Client, dict]:
        c, _, d = await _client(req)
        if c.status != "approved":
            raise HTTPException(403, "Rechner ist nicht freigegeben")
        return c, d

    @r.post("/client/backup/upload")
    async def backup_upload(req: Request):
        c, d = await _approved(req)
        blob = d.get("blob")
        if not isinstance(blob, str) or not blob or len(blob) > BACKUP_MAX:
            raise HTTPException(400, f"Sicherung fehlt oder ist zu groß (max. {BACKUP_MAX // 1000} KB)")
        try:
            if json.loads(blob).get("format") != "vera-connect-sealed-1":
                raise ValueError
        except (ValueError, AttributeError) as e:
            raise HTTPException(400, "Sicherung muss auf dem Rechner verschlüsselt sein") from e
        m = d.get("meta") or {}
        meta = {"tunnels": [str(x)[:32] for x in (m.get("tunnels") or [])][:50], "vera_tunnel": str(m.get("vera_tunnel") or "")[:32],
                "default": str(m.get("default") or "")[:32], "client_version": str(m.get("client_version") or "")[:16],
                "hostname": str(m.get("hostname") or c.hostname)[:64], "comment": str(m.get("comment") or "")[:200]}
        with session() as s:
            b = Backup(client_id=c.id, meta=meta, blob=blob, size=len(blob))
            s.add(b)
            s.flush()
            bid = b.id
            _prune(s, c.id)
            x = s.get(Client, c.id)
            _hist(x, f"Sicherung angelegt ({len(meta['tunnels'])} eigene Tunnel)")
        core.audit(c.hostname or c.machine_id[:12], "VERA-Connect: Sicherung angelegt", meta["comment"],
                   ip=req.client.host if req.client else "")
        return {"id": bid, "keep": backup_keep()}

    @r.post("/client/backup/list")
    async def backup_list(req: Request):
        c, _ = await _approved(req)
        with session() as s:
            rows = s.scalars(select(Backup).where(Backup.client_id == c.id).order_by(Backup.created.desc(), Backup.id.desc())).all()
            return {"backups": [backup_dict(b) for b in rows], "keep": backup_keep()}

    @r.post("/client/backup/get")
    async def backup_get(req: Request):
        c, d = await _approved(req)
        with session() as s:
            b = s.get(Backup, int(d.get("id") or 0))
            if not b or b.client_id != c.id:
                raise HTTPException(404, "Sicherung unbekannt")
            out = {**backup_dict(b), "blob": b.blob}
            x = s.get(Client, c.id)
            _hist(x, f"Sicherung vom {out['created_local']} abgeholt")
        core.audit(c.hostname or c.machine_id[:12], "VERA-Connect: Sicherung abgeholt", out["created_local"],
                   ip=req.client.host if req.client else "")
        return out

    @r.post("/client/backup/delete")
    async def backup_delete(req: Request):
        c, d = await _approved(req)
        with session() as s:
            b = s.get(Backup, int(d.get("id") or 0))
            if not b or b.client_id != c.id:
                raise HTTPException(404, "Sicherung unbekannt")
            s.delete(b)
            _hist(s.get(Client, c.id), "Sicherung gelöscht")
        return {"ok": True}

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
            "history": list(reversed(c.history or [])),
            "fingerprint": _fp(c.fingerprint), "key_storage": c.key_storage or "",
            "credential_at": c.credential_at.isoformat() if c.credential_at else None,
            "pending_key": key_fp(c.pending_key), "pending_storage": c.pending_storage or "",
            "pending_since": c.pending_since.isoformat() if c.pending_since else None,
            "pending_fp": _fp(c.pending_fp), "pending_match": compare(_fp(c.pending_fp), _fp(c.fingerprint)) if c.pending_key else "",
            "suggested_id": c.suggested_id, "match_quality": c.match_quality or ""}


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
            counts = dict(s.execute(select(Backup.client_id, func.count(Backup.id)).group_by(Backup.client_id)).all())
            all_c = list(s.scalars(select(Client).order_by(Client.status != "pending", Client.hostname)))
            names = {c.id: c.hostname or c.machine_id[:12] for c in all_c}
            rk = set(s.scalars(select(RevokedKey.public_key)))
            rows = [client_dict(c, peers) | {"backups": counts.get(c.id, 0), "suggested_name": names.get(c.suggested_id, ""),
                                             "key_revoked": c.public_key in rk}
                    for c in all_c]
        return {"clients": rows, "enroll_key": setting("enroll_key") if u["level"] == "admin" else None,
                "enroll_key_set": bool(setting("enroll_key")), "allow_disconnect": setting("allow_disconnect", "1") == "1",
                "backup_keep": backup_keep(), "fp_labels": FP_LABELS, "signer": signing_public()}

    @r.get("/{cid}/backups")
    def client_backups(cid: int, u=Depends(read)):
        with session() as s:
            rows = s.scalars(select(Backup).where(Backup.client_id == cid).order_by(Backup.created.desc(), Backup.id.desc())).all()
            return {"backups": [backup_dict(b) for b in rows], "keep": backup_keep()}

    @r.delete("/{cid}/backups/{bid}")
    def client_backup_delete(cid: int, bid: int, u=Depends(admin)):
        with session() as s:
            b = s.get(Backup, bid)
            if not b or b.client_id != cid:
                raise HTTPException(404, "Sicherung unbekannt")
            s.delete(b)
            c = s.get(Client, cid)
            name = c.hostname if c else str(cid)
            if c:
                _hist(c, f"Sicherung gelöscht von {u['name']}")
        host.audit(u, "VERA-Connect: Sicherung gelöscht", name)
        return {"ok": True}

    @r.post("/{cid}/backups/{bid}/copy")
    async def client_backup_copy(cid: int, bid: int, req: Request, u=Depends(admin)):
        """Hand a backup to another computer (e.g. new hardware) – it can restore it with the passphrase."""
        target = int((await req.json()).get("target") or 0)
        with session() as s:
            b, src, dst = s.get(Backup, bid), s.get(Client, cid), s.get(Client, target)
            if not b or b.client_id != cid or not src:
                raise HTTPException(404, "Sicherung unbekannt")
            if not dst or target == cid:
                raise HTTPException(400, "Ziel-Rechner unbekannt")
            s.add(Backup(client_id=target, meta=dict(b.meta or {}), blob=b.blob, size=b.size,
                         origin=f"kopiert von {src.hostname or src.machine_id[:12]} ({_local(b.created)})"))
            _hist(dst, f"Sicherung von {src.hostname} übertragen durch {u['name']}")
            names = (src.hostname, dst.hostname)
        host.audit(u, "VERA-Connect: Sicherung übertragen", f"{names[0]} → {names[1]}")
        return {"ok": True}

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
            if revoked(s, c.public_key):
                raise HTTPException(409, "Der Geräteschlüssel dieses Rechners ist gesperrt – erst einen neuen Schlüssel übernehmen")
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
            c.suggested_id, c.match_quality = None, ""
            issue_credential(c)
            _hist(c, f"freigegeben von {u['name']} – Ausweis ausgestellt")
            res = client_dict(c, _peers())
        host.audit(u, "VERA-Connect: Rechner freigegeben", res["hostname"], details=f"Zugang {res['peer_name']} · Tunnel {tn}")
        return res

    @r.post("/{cid}/block")
    async def block(cid: int, req: Request, u=Depends(admin)):
        """revoke=true: the device key goes onto the revocation list as well – the computer has to enrol with a new key
        (VERA-Connect reinstalled), an admin takes that key over and approves again."""
        try:
            d = json.loads(await req.body() or b"{}")
        except ValueError:
            d = {}
        rev = bool(isinstance(d, dict) and d.get("revoke"))
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            c.status = "blocked"
            if rev:
                revoke(s, c, f"gesperrt von {u['name']}")
                c.credential, c.credential_at = "", None
            _hist(c, f"gesperrt von {u['name']}" + (" – Geräteschlüssel gesperrt" if rev else ""))
            name = c.hostname
        host.audit(u, "VERA-Connect: Rechner gesperrt", name, details="Geräteschlüssel gesperrt" if rev else "")
        return {"ok": True}

    @r.post("/{cid}/accept_key")
    def accept_key(cid: int, u=Depends(admin)):
        """The new key of this machine id (pending_key) replaces the pinned one; the old key is revoked."""
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            if not c.pending_key:
                raise HTTPException(400, "Es wartet kein neuer Geräteschlüssel")
            if revoked(s, c.pending_key):
                raise HTTPException(409, "Der neue Schlüssel ist gesperrt")
            revoke(s, c, f"ersetzt durch neuen Schlüssel ({u['name']})")
            c.public_key, c.key_storage = c.pending_key, c.pending_storage or c.key_storage
            if _fp(c.pending_fp):
                c.fingerprint = c.pending_fp
            c.pending_key, c.pending_fp, c.pending_storage, c.pending_since, c.note = "", "", "", None, ""
            c.credential, c.credential_at = "", None
            if c.status == "approved":
                issue_credential(c)
            _hist(c, f"neuen Geräteschlüssel übernommen ({u['name']})")
            name = c.hostname
            res = client_dict(c, _peers())
        host.audit(u, "VERA-Connect: Geräteschlüssel übernommen", name)
        return res

    @r.post("/{cid}/discard_key")
    def discard_key(cid: int, u=Depends(admin)):
        """Refuse the waiting new key (it goes onto the revocation list)."""
        with session() as s:
            c = s.get(Client, cid)
            if not c or not c.pending_key:
                raise HTTPException(404, "Es wartet kein neuer Geräteschlüssel")
            revoke(s, c, f"neuer Schlüssel abgelehnt ({u['name']})", key=c.pending_key)
            c.pending_key, c.pending_fp, c.pending_storage, c.pending_since = "", "", "", None
            _hist(c, f"neuen Geräteschlüssel abgelehnt ({u['name']})")
            name = c.hostname
        host.audit(u, "VERA-Connect: neuer Geräteschlüssel abgelehnt", name)
        return {"ok": True}

    @r.post("/{cid}/replace")
    async def replace(cid: int, req: Request, u=Depends(admin)):
        """Umtragen: the waiting entry cid (new hardware / reinstalled Windows) takes over the identity of target –
        WireGuard access, tunnel, backups and history stay at target; the old key of target is revoked."""
        target = int((await req.json()).get("target") or 0)
        with session() as s:
            new, old = s.get(Client, cid), s.get(Client, target)
            if not new or not old or new.id == old.id:
                raise HTTPException(404, "Rechner nicht gefunden")
            if new.status != "pending" or old.status == "pending":
                raise HTTPException(400, "Umtragen nur von einem wartenden auf einen bekannten Rechner")
            if revoked(s, new.public_key):
                raise HTTPException(409, "Der Schlüssel des wartenden Rechners ist gesperrt")
            revoke(s, old, f"ersetzt durch {new.hostname or new.machine_id[:12]} ({u['name']})")
            if old.pending_key:
                revoke(s, old, "verworfen beim Umtragen", key=old.pending_key)
            vals = {f: getattr(new, f) for f in ("machine_id", "public_key", "key_storage", "fingerprint", "hostname", "domain",
                                                 "username", "os", "client_version", "last_seen", "last_ip")}
            new_hist = list(new.history or [])
            s.delete(new)
            s.flush()                                               # machine_id is unique
            for f, v in vals.items():
                setattr(old, f, v)
            old.pending_key, old.pending_fp, old.pending_storage, old.pending_since = "", "", "", None
            old.suggested_id, old.match_quality, old.note = None, "", ""
            old.status, old.approved_by, old.approved_at = "approved", u["name"], now()
            old.config_hash = ""                                     # the new computer has nothing installed yet
            old.history = (list(old.history or []) + new_hist[-5:])[-30:]
            issue_credential(old)
            _hist(old, f"umgetragen von {u['name']}: neuer Rechner/Schlüssel übernimmt diesen Eintrag")
            for o in s.scalars(select(Client).where(Client.suggested_id == cid)):
                o.suggested_id = old.id
            res = client_dict(old, _peers())
        host.audit(u, "VERA-Connect: Rechner umgetragen", res["hostname"], details=f"wartender Eintrag {cid} → Rechner {target}")
        return res

    @r.delete("/{cid}")
    def remove(cid: int, u=Depends(admin)):
        with session() as s:
            c = s.get(Client, cid)
            if not c:
                raise HTTPException(404, "Rechner nicht gefunden")
            name = c.hostname
            s.delete(c)
            for o in s.scalars(select(Client).where(Client.suggested_id == cid)):
                o.suggested_id, o.match_quality = None, ""
            n = 0
            for b in s.scalars(select(Backup).where(Backup.client_id == cid)).all():
                s.delete(b)
                n += 1
        host.audit(u, "VERA-Connect: Rechner entfernt", name,
                   details="Der WireGuard-Zugang bleibt bestehen" + (f", {n} Sicherung(en) gelöscht" if n else ""))
        return {"ok": True}

    @r.put("/settings")
    async def settings(req: Request, u=Depends(admin)):
        d = await req.json()
        if "enroll_key" in d:
            v = d["enroll_key"]
            set_setting("enroll_key", ("vk_" + secrets.token_urlsafe(18)) if v == "new" else "")
        if "allow_disconnect" in d:
            set_setting("allow_disconnect", "1" if d["allow_disconnect"] else "0")
        if "backup_keep" in d:
            try:
                set_setting("backup_keep", str(max(1, min(200, int(d["backup_keep"] or 20)))))
            except (TypeError, ValueError) as e:
                raise HTTPException(400, "Anzahl der Sicherungen: Zahl 1–200") from e
        host.audit(u, "VERA-Connect: Einstellungen geändert", "", details=json.dumps({k: (v if k != "enroll_key" else "…") for k, v in d.items()}))
        return {"enroll_key": setting("enroll_key"), "allow_disconnect": setting("allow_disconnect", "1") == "1", "backup_keep": backup_keep()}

    # ---- installer with built-in settings (VERA address, update server, keys)
    @r.get("/installer/settings")
    def installer_settings(req: Request, u=Depends(admin)):
        return _installer_info(req)

    @r.put("/installer/settings")
    async def installer_settings_set(req: Request, u=Depends(admin)):
        d = await req.json()
        for k in ("vera_url", "update_url", "update_key", "uma_enroll_key", "tunnel", "base_url"):
            if k in d:
                set_setting("installer_" + k, (d[k] or "").strip())
        host.audit(u, "VERA-Connect: Installer-Einstellungen geändert", "", details=json.dumps({k: v for k, v in d.items() if k not in ("update_key", "uma_enroll_key")}))
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
               "uma_enroll_key": info["uma_enroll_key"], "enroll_key": setting("enroll_key"), "tunnel": info["tunnel"]}
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
            "uma_enroll_key": setting("installer_uma_enroll_key"),
            "tunnel": setting("installer_tunnel"), "base_url": setting("installer_base_url") or BASE_EXE_URL,
            "base": base if os.path.exists(BASE_EXE) else None, "enroll_key_set": bool(setting("enroll_key"))}
