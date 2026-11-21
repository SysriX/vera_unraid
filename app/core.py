"""VERA core: settings, encryption, database, users, sessions, firewalls, audit log.

Database: MariaDB/MySQL via DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD (or VERA_DB_URL);
without DB_HOST an SQLite file in /config is used.
Secrets (OPNsense API keys, WireGuard private keys) are encrypted with Fernet; key in /config/secret.key
or the environment variable VERA_KEY.
"""
from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import quote_plus

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

VERSION = "1.2.2"
DATA = os.environ.get("VERA_DATA", "/config")
KEY_FILE = os.path.join(DATA, "secret.key")


def now() -> datetime:
    return datetime.now(timezone.utc)


def log(*a):
    print("[vera]", *a, flush=True)


# ------------------------------------------------------------------ encryption
_fernet: Fernet | None = None


def fernet() -> Fernet:
    global _fernet
    if _fernet:
        return _fernet
    key = os.environ.get("VERA_KEY", "").strip()
    if not key:
        os.makedirs(DATA, exist_ok=True)
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, encoding="utf-8") as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key().decode()
            with open(KEY_FILE, "w", encoding="utf-8") as f:
                f.write(key + "\n")
            try:
                os.chmod(KEY_FILE, 0o600)
            except OSError:
                pass
            log("Neuer Schlüssel angelegt:", KEY_FILE, "– mit sichern, sonst sind gespeicherte Schlüssel verloren!")
    _fernet = Fernet(key.encode())
    return _fernet


def encrypt(value) -> str:
    return fernet().encrypt(json.dumps(value).encode()).decode()


def decrypt(token: str):
    if not token:
        return ""
    try:
        return json.loads(fernet().decrypt(token.encode()))
    except InvalidToken as e:
        raise RuntimeError("Gespeicherte Schlüssel lassen sich nicht entschlüsseln – falscher secret.key?") from e


# ------------------------------------------------------------------ tables
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "vera_user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(16), default="read")          # read | write | admin
    pw_hash: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserSession(Base):
    __tablename__ = "vera_session"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str] = mapped_column(String(64), default="")


class Firewall(Base):
    __tablename__ = "vera_firewall"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    url: Mapped[str] = mapped_column(String(255), default="")
    secrets_enc: Mapped[str] = mapped_column(Text, default="")          # {"api_key", "api_secret"}
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    site_name: Mapped[str] = mapped_column(String(128), default="")
    endpoint_host: Mapped[str] = mapped_column(String(255), default="")
    client_allowed_ips: Mapped[str] = mapped_column(String(1024), default="")
    client_dns: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(512), default="")
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApiToken(Base):
    """Access for another app (e.g. MIRA). Created by pairing with a VERA admin login; only the hash is stored."""
    __tablename__ = "vera_api_token"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="")              # e.g. "MIRA (mira.local)"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default="admin")         # read | write | admin (upper limit)
    created_by: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ip: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AuditLog(Base):
    __tablename__ = "vera_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    username: Mapped[str] = mapped_column(String(128), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(128), default="")
    target: Mapped[str] = mapped_column(String(512), default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    details: Mapped[str] = mapped_column(Text, default="")


# ------------------------------------------------------------------ database
def db_url() -> str:
    if os.environ.get("VERA_DB_URL"):
        return os.environ["VERA_DB_URL"]
    host = os.environ.get("DB_HOST", "").strip()
    if not host:
        return "sqlite:///" + os.path.join(DATA, "vera.db")
    user, pw = os.environ.get("DB_USER", "vera"), os.environ.get("DB_PASSWORD", "")
    return (f"mysql+pymysql://{quote_plus(user)}:{quote_plus(pw)}@{host}:{int(os.environ.get('DB_PORT') or 3306)}/"
            f"{os.environ.get('DB_NAME', 'vera')}?charset=utf8mb4")


engine = None
_sm: sessionmaker | None = None


def db_start():
    global engine, _sm
    url = db_url()
    args = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        os.makedirs(DATA, exist_ok=True)
        args["connect_args"] = {"check_same_thread": False}
    else:
        args["pool_recycle"] = 1800
    engine = create_engine(url, **args)
    Base.metadata.create_all(engine)
    _sm = sessionmaker(engine, expire_on_commit=False)
    log("Datenbank:", "MariaDB/MySQL" if url.startswith("mysql") else "SQLite")


@contextmanager
def session() -> Session:
    s = _sm()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def audit(username: str, action: str, target: str = "", ok: bool = True, details: str = "", ip: str = "") -> None:
    try:
        with session() as s:
            s.add(AuditLog(username=username, action=action, target=str(target)[:512], ok=ok,
                           details=str(details)[:8000], ip=ip))
    except Exception as e:  # noqa: BLE001
        log("Protokoll fehlgeschlagen:", e)


def firewall_values(fw: Firewall) -> dict:
    sec = decrypt(fw.secrets_enc) or {}
    return {"name": fw.name, "url": fw.url, "api_key": sec.get("api_key", ""), "api_secret": sec.get("api_secret", ""),
            "verify_tls": fw.verify_tls, "site_name": fw.site_name or fw.name, "endpoint_host": fw.endpoint_host,
            "client_allowed_ips": fw.client_allowed_ips, "client_dns": fw.client_dns}


def user_count() -> int:
    with session() as s:
        return len(list(s.scalars(select(User.id))))


def token() -> str:
    return secrets.token_urlsafe(32)


def instance_id() -> str:
    """Stable id of this VERA installation (lets MIRA recognise one VERA reachable under several addresses)."""
    p = os.path.join(DATA, "instance-id")
    try:
        with open(p, encoding="utf-8") as f:
            v = f.read().strip()
        if v:
            return v
    except OSError:
        pass
    v = secrets.token_hex(8)
    try:
        os.makedirs(DATA, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(v + "\n")
    except OSError:
        pass
    return v
