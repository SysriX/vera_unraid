"""VERA – VPN Endpoint & Remote Access. WireGuard management for OPNsense (standalone)."""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select

import clients
import core
from core import ApiToken, AuditLog, Firewall, User, UserSession, now, session
from wgcore.api import build_router, build_share_router
from wgcore.models import Instance, Peer, Store
from wgcore.service import Service

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
COOKIE = "vera_session"
SESSION_TTL = timedelta(hours=12)
LEVELS = {"read": 1, "write": 2, "admin": 3}
ph = PasswordHasher()
SETUP = {"code": None}
_store: Store | None = None


def store() -> Store:
    global _store
    if _store is None:
        _store = Store(core.engine, core.encrypt, lambda t: core.decrypt(t) or "")
    return _store


def setup_code_announce():
    if core.user_count():
        SETUP["code"] = None
        return
    code = os.environ.get("VERA_SETUP_CODE") or "-".join(secrets.token_hex(2).upper() for _ in range(3))
    SETUP["code"] = code
    try:
        with open(os.path.join(core.DATA, "setup-code.txt"), "w", encoding="utf-8") as f:
            f.write(code + "\n")
    except OSError:
        pass
    core.log("=" * 60)
    core.log("Ersteinrichtung: Code für die Weboberfläche:", code)
    core.log("=" * 60)


@asynccontextmanager
async def lifespan(app):
    core.fernet()
    core.db_start()
    store()
    setup_code_announce()
    core.log(f"VERA {core.VERSION} bereit")
    yield


app = FastAPI(title="VERA", version=core.VERSION, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware("http")
async def protect(req: Request, call_next):
    # CSRF: browser calls need the X-VERA header; apps with an API token (Bearer) and pairing don't use cookies
    bearer = req.headers.get("authorization", "").startswith("Bearer ")
    if req.url.path.startswith("/api/") and req.method in ("POST", "PUT", "PATCH", "DELETE") \
            and req.headers.get("x-vera") != "1" and not bearer and req.url.path != "/api/connect/pair":
        return JSONResponse({"detail": "Header X-VERA fehlt"}, status_code=403)
    resp = await call_next(req)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'")
    if req.url.path.startswith("/api/") or req.url.path.startswith(("/wg-share/", "/client/")):
        resp.headers.setdefault("Cache-Control", "no-store")
    elif req.url.path.startswith("/static/"):
        resp.headers.setdefault("Cache-Control", "no-cache")
    return resp


@app.exception_handler(RuntimeError)
async def _runtime(req, e):
    core.log("Fehler:", repr(e))
    return JSONResponse({"detail": str(e)}, status_code=500)


# ------------------------------------------------------------------ auth
def client_ip(req: Request) -> str:
    return req.client.host if req.client else ""


def _aware(t):
    return t.replace(tzinfo=t.tzinfo or core.timezone.utc) if t else None


def _token_user(req: Request, raw: str) -> dict:
    """Another app (e.g. MIRA) with an API token. X-Acting-Role can only lower the token's role."""
    with session() as s:
        t = s.scalar(select(ApiToken).where(ApiToken.token_hash == hashlib.sha256(raw.encode()).hexdigest()))
        if not t or not t.enabled:
            raise HTTPException(401, "API-Schlüssel ungültig oder widerrufen")
        level = t.role
        acting = req.headers.get("x-acting-role", "")
        if acting in LEVELS and LEVELS[acting] < LEVELS.get(level, 0):
            level = acting
        last = _aware(t.last_used)
        if not last or (now() - last).total_seconds() > 60:
            t.last_used, t.last_ip = now(), client_ip(req)
        actor = (req.headers.get("x-acting-user") or "").strip()[:64]
        name = f"{t.name} · {actor}" if actor else t.name
        return {"id": None, "name": name, "display_name": name, "level": level, "token_id": t.id,
                "ip": (req.headers.get("x-acting-ip") or client_ip(req))[:64]}


def current_user(req: Request) -> dict:
    auth = req.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return _token_user(req, auth[7:].strip())
    tok = req.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, "nicht angemeldet")
    th = hashlib.sha256(tok.encode()).hexdigest()
    with session() as s:
        se = s.get(UserSession, th)
        exp = se.expires_at.replace(tzinfo=se.expires_at.tzinfo or core.timezone.utc) if se else None
        if not se or exp < now():
            if se:
                s.delete(se)
            raise HTTPException(401, "Sitzung abgelaufen")
        u = s.get(User, se.user_id)
        if not u or not u.enabled:
            s.delete(se)
            raise HTTPException(401, "Benutzer gesperrt")
        if (now() + SESSION_TTL - exp).total_seconds() > 600:
            se.expires_at = now() + SESSION_TTL
        return {"id": u.id, "name": u.username, "display_name": u.display_name or u.username, "level": u.role,
                "ip": client_ip(req)}


def require(level: str):
    def check(u: dict = Depends(current_user)) -> dict:
        if LEVELS.get(u["level"], 0) < LEVELS[level]:
            raise HTTPException(403, "Dafür fehlen die Rechte")
        return u
    return check


_fails: dict[str, list[float]] = {}
_fails_lock = threading.Lock()


def _too_many(ip: str) -> bool:
    with _fails_lock:
        lst = [t for t in _fails.get(ip, []) if time.time() - t < 600]
        _fails[ip] = lst
        return len(lst) >= 8


def _failed(ip: str):
    with _fails_lock:
        _fails.setdefault(ip, []).append(time.time())


def _new_session(resp: Response, req: Request, user_id: int):
    tok = core.token()
    with session() as s:
        s.add(UserSession(token_hash=hashlib.sha256(tok.encode()).hexdigest(), user_id=user_id,
                          expires_at=now() + SESSION_TTL, ip=client_ip(req)))
        s.execute(delete(UserSession).where(UserSession.expires_at < now()))
    secure = req.url.scheme == "https" or req.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(COOKIE, tok, httponly=True, samesite="strict", secure=secure, max_age=int(SESSION_TTL.total_seconds()))


def _check_password(pw: str):
    if len(pw or "") < 12:
        raise HTTPException(400, "Passwort: mindestens 12 Zeichen")


@app.get("/api/state")
def state():
    return {"setup_needed": SETUP["code"] is not None, "version": core.VERSION}


@app.post("/api/setup")
async def setup(req: Request, resp: Response):
    d = await req.json()
    if SETUP["code"] is None:
        raise HTTPException(409, "VERA ist bereits eingerichtet")
    if not secrets.compare_digest((d.get("code") or "").strip().upper(), SETUP["code"]):
        _failed(client_ip(req))
        raise HTTPException(403, "Einrichtungs-Code stimmt nicht (siehe Log des Containers)")
    name = (d.get("username") or "").strip()
    if not name:
        raise HTTPException(400, "Benutzername fehlt")
    _check_password(d.get("password"))
    with session() as s:
        u = User(username=name, display_name=d.get("display_name") or name, role="admin", pw_hash=ph.hash(d["password"]))
        s.add(u)
        s.flush()
        uid = u.id
    SETUP["code"] = None
    try:
        os.remove(os.path.join(core.DATA, "setup-code.txt"))
    except OSError:
        pass
    core.audit(name, "Ersteinrichtung", name, ip=client_ip(req))
    _new_session(resp, req, uid)
    return {"ok": True}


@app.post("/api/login")
async def login(req: Request, resp: Response):
    ip = client_ip(req)
    if _too_many(ip):
        raise HTTPException(429, "Zu viele Fehlversuche – bitte 10 Minuten warten")
    d = await req.json()
    with session() as s:
        u = s.scalar(select(User).where(User.username == (d.get("username") or "").strip()))
        ok = False
        if u and u.enabled and u.pw_hash:
            try:
                ok = ph.verify(u.pw_hash, d.get("password") or "")
            except VerifyMismatchError:
                ok = False
        if not ok:
            _failed(ip)
            core.audit(d.get("username", ""), "Anmeldung fehlgeschlagen", ok=False, ip=ip)
            raise HTTPException(401, "Benutzer oder Passwort falsch")
        if ph.check_needs_rehash(u.pw_hash):
            u.pw_hash = ph.hash(d["password"])
        u.last_login = now()
        uid, name = u.id, u.username
    _new_session(resp, req, uid)
    core.audit(name, "Anmeldung", ip=ip)
    return {"ok": True}


@app.post("/api/logout")
def logout(req: Request, resp: Response):
    tok = req.cookies.get(COOKIE)
    if tok:
        with session() as s:
            s.execute(delete(UserSession).where(UserSession.token_hash == hashlib.sha256(tok.encode()).hexdigest()))
    resp.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(u=Depends(current_user)):
    return u


@app.post("/api/me/password")
async def my_password(req: Request, u=Depends(current_user)):
    d = await req.json()
    _check_password(d.get("new"))
    with session() as s:
        usr = s.get(User, u["id"])
        try:
            ph.verify(usr.pw_hash, d.get("old") or "")
        except VerifyMismatchError as e:
            raise HTTPException(400, "Altes Passwort stimmt nicht") from e
        usr.pw_hash = ph.hash(d["new"])
    core.audit(u["name"], "Eigenes Passwort geändert", ip=u["ip"])
    return {"ok": True}


# ------------------------------------------------------------------ connect (other apps, e.g. MIRA)
@app.get("/.well-known/sysrix-app")
def sysrix_app():
    """Discovery: lets MIRA (and other SysriX tools) find VERA in the network."""
    return {"app": "vera", "name": "VERA", "title": "VPN Endpoint & Remote Access", "version": core.VERSION,
            "connect": 1, "pair": "/api/connect/pair", "instance": core.instance_id(),
            "setup_needed": SETUP["code"] is not None}


@app.post("/api/connect/pair")
async def connect_pair(req: Request):
    """One-time login of a VERA admin → API token for the calling app. The password is not stored anywhere."""
    ip = client_ip(req)
    if _too_many(ip):
        raise HTTPException(429, "Zu viele Fehlversuche – bitte 10 Minuten warten")
    d = await req.json()
    username = (d.get("username") or "").strip()
    with session() as s:
        u = s.scalar(select(User).where(User.username == username))
        ok = False
        if u and u.enabled and u.pw_hash:
            try:
                ok = ph.verify(u.pw_hash, d.get("password") or "")
            except VerifyMismatchError:
                ok = False
        if not ok:
            _failed(ip)
            core.audit(username, "App-Verbindung fehlgeschlagen", (d.get("client") or "")[:100], ok=False, ip=ip)
            raise HTTPException(401, "Benutzer oder Passwort falsch")
        if u.role != "admin":
            raise HTTPException(403, "Nur ein VERA-Admin kann Apps verbinden")
        role = d.get("role") if d.get("role") in LEVELS else "admin"
        raw = "vera_" + core.token()
        t = ApiToken(name=(d.get("client") or "App").strip()[:128], token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                     role=role, created_by=username, last_ip=ip)
        s.add(t)
        s.flush()
        tid, tname = t.id, t.name
    core.audit(username, "App verbunden", tname, details=f"Rolle {role}, Schlüssel #{tid}", ip=ip)
    return {"token": raw, "token_id": tid, "role": role, "app": "vera", "name": "VERA", "version": core.VERSION}


def token_dict(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "role": t.role, "created_by": t.created_by, "enabled": t.enabled,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "last_used": t.last_used.isoformat() if t.last_used else None, "last_ip": t.last_ip}


@app.get("/api/connect/tokens")
def connect_tokens(u=Depends(require("admin"))):
    with session() as s:
        return {"tokens": [token_dict(t) for t in s.scalars(select(ApiToken).order_by(ApiToken.id))]}


@app.delete("/api/connect/tokens/{tid}")
def connect_token_delete(tid: int, u=Depends(current_user)):
    """Admins revoke any key; a connected app may always revoke its own key (when it is removed there)."""
    if LEVELS.get(u["level"], 0) < LEVELS["admin"] and u.get("token_id") != tid:
        raise HTTPException(403, "Dafür fehlen die Rechte")
    with session() as s:
        t = s.get(ApiToken, tid)
        if not t:
            raise HTTPException(404, "Schlüssel nicht gefunden")
        name = t.name
        s.delete(t)
    core.audit(u["name"], "App-Zugriff widerrufen", name, ip=u["ip"])
    return {"ok": True}


# ------------------------------------------------------------------ firewalls
def fw_dict(f: Firewall) -> dict:
    sec = core.decrypt(f.secrets_enc) or {}
    return {"id": f.id, "name": f.name, "url": f.url, "verify_tls": f.verify_tls, "site_name": f.site_name,
            "endpoint_host": f.endpoint_host, "client_allowed_ips": f.client_allowed_ips, "client_dns": f.client_dns,
            "enabled": f.enabled, "status": f.status, "checked_at": f.checked_at.isoformat() if f.checked_at else None,
            "has_api_key": bool(sec.get("api_key")), "has_api_secret": bool(sec.get("api_secret"))}


FW_FIELDS = ("name", "url", "site_name", "endpoint_host", "client_allowed_ips", "client_dns")


def _apply_fw(f: Firewall, d: dict):
    for k in FW_FIELDS:
        if k in d:
            setattr(f, k, (d[k] or "").strip())
    for k in ("verify_tls", "enabled"):
        if k in d:
            setattr(f, k, bool(d[k]))
    sec = core.decrypt(f.secrets_enc) or {}
    for k in ("api_key", "api_secret"):
        if d.get(k):
            sec[k] = d[k].strip()
    f.secrets_enc = core.encrypt(sec)
    if not f.name:
        raise HTTPException(400, "Name fehlt")
    if not f.url.startswith(("http://", "https://")):
        raise HTTPException(400, "Adresse muss mit https:// (oder http://) beginnen")
    f.updated_at = now()


@app.get("/api/firewalls")
def firewalls(u=Depends(require("read"))):
    with session() as s:
        return {"firewalls": [fw_dict(f) for f in s.scalars(select(Firewall).order_by(Firewall.name))]}


@app.post("/api/firewalls")
async def firewall_create(req: Request, u=Depends(require("admin"))):
    d = await req.json()
    with session() as s:
        f = Firewall()
        _apply_fw(f, d)
        s.add(f)
        s.flush()
        res = fw_dict(f)
    core.audit(u["name"], "Firewall angelegt", res["name"], ip=u["ip"])
    return res


@app.put("/api/firewalls/{fid}")
async def firewall_update(fid: int, req: Request, u=Depends(require("admin"))):
    d = await req.json()
    with session() as s:
        f = s.get(Firewall, fid)
        if not f:
            raise HTTPException(404, "Firewall nicht gefunden")
        _apply_fw(f, d)
        res = fw_dict(f)
    core.audit(u["name"], "Firewall geändert", res["name"], ip=u["ip"])
    return res


@app.delete("/api/firewalls/{fid}")
def firewall_delete(fid: int, u=Depends(require("admin"))):
    with session() as s:
        f = s.get(Firewall, fid)
        if not f:
            raise HTTPException(404, "Firewall nicht gefunden")
        name = f.name
        s.delete(f)
    with store().session() as s:   # only VERA's records – nothing is removed on the OPNsense
        s.execute(delete(Peer).where(Peer.firewall_id == fid))
        s.execute(delete(Instance).where(Instance.firewall_id == fid))
    core.audit(u["name"], "Firewall entfernt", name, ip=u["ip"])
    return {"ok": True}


def _test(values: dict, fid: int | None) -> str:
    svc = Service(store(), fid or 0, values)
    try:
        return svc.test()
    finally:
        svc.close()


@app.post("/api/firewalls/{fid}/test")
def firewall_test(fid: int, u=Depends(require("read"))):
    with session() as s:
        f = s.get(Firewall, fid)
        if not f:
            raise HTTPException(404, "Firewall nicht gefunden")
        vals = core.firewall_values(f)
    try:
        msg, ok = _test(vals, fid), True
    except Exception as e:  # noqa: BLE001
        msg, ok = str(e), False
    with session() as s:
        f = s.get(Firewall, fid)
        f.status, f.checked_at = ("ok: " if ok else "fehler: ") + msg[:480], now()
    if not ok:
        raise HTTPException(400, msg)
    return {"status": msg}


@app.post("/api/firewalls/test")
async def firewall_test_unsaved(req: Request, u=Depends(require("admin"))):
    d = await req.json()
    vals = {k: d.get(k, "") for k in ("url", "api_key", "api_secret", "site_name", "name")}
    vals["verify_tls"] = bool(d.get("verify_tls"))
    if d.get("id") and (not vals["api_key"] or not vals["api_secret"]):
        with session() as s:
            f = s.get(Firewall, int(d["id"]))
            if f:
                old = core.firewall_values(f)
                vals["api_key"] = vals["api_key"] or old["api_key"]
                vals["api_secret"] = vals["api_secret"] or old["api_secret"]
    try:
        return {"status": _test(vals, None)}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e)) from e


# ------------------------------------------------------------------ users + audit
def user_dict(x: User) -> dict:
    return {"id": x.id, "username": x.username, "display_name": x.display_name, "role": x.role, "enabled": x.enabled,
            "last_login": x.last_login.isoformat() if x.last_login else None}


@app.get("/api/users")
def users(u=Depends(require("admin"))):
    with session() as s:
        return {"users": [user_dict(x) for x in s.scalars(select(User).order_by(User.username))]}


@app.post("/api/users")
async def user_create(req: Request, u=Depends(require("admin"))):
    d = await req.json()
    name = (d.get("username") or "").strip()
    if not name:
        raise HTTPException(400, "Benutzername fehlt")
    _check_password(d.get("password"))
    with session() as s:
        if s.scalar(select(User).where(User.username == name)):
            raise HTTPException(400, "Benutzer gibt es schon")
        x = User(username=name, display_name=d.get("display_name") or name,
                 role=d.get("role") if d.get("role") in LEVELS else "read", pw_hash=ph.hash(d["password"]))
        s.add(x)
        s.flush()
        res = user_dict(x)
    core.audit(u["name"], "Benutzer angelegt", name, ip=u["ip"])
    return res


@app.put("/api/users/{uid}")
async def user_update(uid: int, req: Request, u=Depends(require("admin"))):
    d = await req.json()
    with session() as s:
        x = s.get(User, uid)
        if not x:
            raise HTTPException(404, "Benutzer nicht gefunden")
        if "display_name" in d:
            x.display_name = d["display_name"] or x.username
        if d.get("role") in LEVELS:
            if x.id == u["id"] and d["role"] != "admin":
                raise HTTPException(400, "Eigene Admin-Rechte kann man sich nicht nehmen")
            x.role = d["role"]
        if "enabled" in d:
            if x.id == u["id"] and not d["enabled"]:
                raise HTTPException(400, "Sich selbst sperren geht nicht")
            x.enabled = bool(d["enabled"])
        if d.get("password"):
            _check_password(d["password"])
            x.pw_hash = ph.hash(d["password"])
        res = user_dict(x)
    core.audit(u["name"], "Benutzer geändert", res["username"], ip=u["ip"])
    return res


@app.delete("/api/users/{uid}")
def user_delete(uid: int, u=Depends(require("admin"))):
    if uid == u["id"]:
        raise HTTPException(400, "Sich selbst löschen geht nicht")
    with session() as s:
        x = s.get(User, uid)
        if not x:
            raise HTTPException(404, "Benutzer nicht gefunden")
        name = x.username
        s.delete(x)
        s.execute(delete(UserSession).where(UserSession.user_id == uid))
    core.audit(u["name"], "Benutzer gelöscht", name, ip=u["ip"])
    return {"ok": True}


@app.get("/api/audit")
def audit_log(limit: int = 300, u=Depends(require("write"))):
    with session() as s:
        rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 2000))))
        return {"rows": [{"time": r.time.isoformat(), "username": r.username, "ip": r.ip, "action": r.action,
                          "target": r.target, "ok": r.ok, "details": r.details} for r in rows]}


# ------------------------------------------------------------------ WireGuard (shared wgcore)
class Host:
    def store(self):
        return store()

    def service(self, fw_id: int) -> Service:
        with session() as s:
            f = s.get(Firewall, int(fw_id))
            if not f or not f.enabled:
                raise LookupError("Firewall nicht gefunden oder ausgeschaltet")
            return Service(store(), f.id, core.firewall_values(f))

    def role(self, level: str):
        return require(level)

    def audit(self, u, action, target="", ok=True, details=""):
        core.audit(u.get("name", "?"), action, target, ok, details, u.get("ip", ""))


_host = Host()
app.include_router(build_router(_host, "/api/wg"))
app.include_router(build_share_router(_host, "/wg-share", "VERA"))
app.include_router(clients.build_public_router(_host))              # VERA-Connect (public, signed)
app.include_router(clients.build_admin_router(_host, store))


@app.get("/health")
def health():
    return {"ok": True, "version": core.VERSION}


@app.get("/api/{rest:path}")
def api_unknown(rest: str):
    raise HTTPException(404, "unbekannt")


app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB, "index.html"), headers={"Cache-Control": "no-cache"})


if __name__ == "__main__":
    import uvicorn
    tls = {}
    if os.environ.get("VERA_TLS_CERT") and os.environ.get("VERA_TLS_KEY"):
        tls = {"ssl_certfile": os.environ["VERA_TLS_CERT"], "ssl_keyfile": os.environ["VERA_TLS_KEY"]}
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("VERA_PORT", "8080")), proxy_headers=True,
                forwarded_allow_ips=os.environ.get("VERA_PROXY_IPS", "127.0.0.1"), log_level="warning",
                server_header=False, **tls)
