#!/usr/bin/env python3
"""mira_plugin.py – build, sign, check and publish MIRA plugins (format 1).

    py tools/mira_plugin.py check   plugin_mira
    py tools/mira_plugin.py keygen  sysrix --out C:/keys            # once per publisher
    py tools/mira_plugin.py sign    plugin_mira --key C:/keys/sysrix.key
    py tools/mira_plugin.py pack    plugin_mira --key C:/keys/sysrix.key --out dist
    py tools/mira_plugin.py verify  dist/vera-1.3.1.zip
    py tools/mira_plugin.py publish dist/vera-1.3.1.zip --url https://plugins.example.org --token pia_…

Environment instead of options: MIRA_PLUGIN_KEY, MIRA_PLUGIN_KEY_ID, PIA_URL, PIA_TOKEN.
Only "keygen", "sign" and "verify" need the package "cryptography"; everything else is stdlib.
The format is described in docs/PLUGIN-FORMAT.md – MIRA and PIA implement the same rules.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

FORMAT = 1
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")
SIGNATURE_FILE = "signature.json"
LEVELS = ("read", "write", "admin")
MAX_FILES = 2000
MAX_UNPACKED = 100 * 1024 * 1024


# ------------------------------------------------------------------ format rules (identical in MIRA and PIA)
def ignored(rel: str) -> bool:
    """Hidden files/folders and __pycache__ are never part of a plugin."""
    return any(part.startswith(".") or part == "__pycache__" for part in rel.split("/"))


def plugin_files(root: str) -> list[tuple[str, str]]:
    """(relative path with "/", absolute path), sorted bytewise by relative path, without signature.json."""
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if not x.startswith(".") and x != "__pycache__"]
        for name in files:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root).replace("\\", "/")
            if ignored(rel) or rel == SIGNATURE_FILE or os.path.islink(p):
                continue
            out.append((rel, p))
    out.sort(key=lambda x: x[0].encode("utf-8"))
    return out


def fingerprint_entries(entries: list[tuple[str, bytes]]) -> str:
    """SHA-256 over: for each file (sorted bytewise by path): path (UTF-8) + SHA-256(content) (32 raw bytes)."""
    h = hashlib.sha256()
    for rel, data in sorted(entries, key=lambda x: x[0].encode("utf-8")):
        h.update(rel.encode("utf-8"))
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def fingerprint_dir(root: str) -> str:
    entries = []
    for rel, p in plugin_files(root):
        with open(p, "rb") as f:
            entries.append((rel, f.read()))
    return fingerprint_entries(entries)


def signed_message(pid: str, version: str, fingerprint: str) -> bytes:
    return f"mira-plugin\n{pid}\n{version}\n{fingerprint}".encode("utf-8")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# ------------------------------------------------------------------ manifest check
def check_manifest(m: dict, files: set[str] | None = None) -> list[str]:
    err = []
    if m.get("format", FORMAT) != FORMAT:
        err.append(f"format muss {FORMAT} sein")
    if not ID_RE.match(str(m.get("id", ""))):
        err.append("id fehlt/ungültig (a–z, 0–9, _ und -, 2–32 Zeichen, beginnt mit Buchstabe)")
    if not VERSION_RE.match(str(m.get("version", ""))):
        err.append("version fehlt/ungültig (z. B. 1.2.0)")
    if not m.get("name"):
        err.append("name fehlt")
    con = m.get("connect") or {}
    if not isinstance(con, dict):
        err.append("connect muss ein Objekt sein")
        con = {}
    proxy = con.get("proxy", ["/api/"])
    if not isinstance(proxy, list) or not all(isinstance(x, str) and x.startswith("/") for x in proxy):
        err.append("connect.proxy muss eine Liste von Pfaden sein, die mit / beginnen")
    elif "/" in proxy:
        err.append("connect.proxy darf nicht „/“ enthalten – nur die Pfade freigeben, die die Oberfläche braucht")
    ui = m.get("ui") or {}
    for key in ("scripts", "styles"):
        for f in ui.get(key, []):
            if files is not None and f not in files:
                err.append(f"ui.{key}: Datei „{f}“ fehlt")
    for v in ui.get("views", []):
        if not v.get("id") or not v.get("title"):
            err.append("ui.views: jede Ansicht braucht id und title")
        if v.get("level") and v["level"] not in LEVELS:
            err.append(f"ui.views[{v.get('id')}]: level muss read, write oder admin sein")
    if m.get("icon") and files is not None and m["icon"] not in files:
        err.append(f"icon „{m['icon']}“ fehlt")
    if m.get("mira_min") and not VERSION_RE.match(str(m["mira_min"])):
        err.append("mira_min ungültig (z. B. 0.6.0)")
    return err


def load_manifest(root: str) -> dict:
    with open(os.path.join(root, "plugin.json"), encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------------ keys
def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:
        sys.exit("Für Schlüssel und Signaturen wird das Paket „cryptography“ gebraucht: py -m pip install cryptography")
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def load_key(path: str):
    serialization, _, _ = _crypto()
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_raw(key) -> bytes:
    serialization, _, _ = _crypto()
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def cmd_keygen(a):
    serialization, Ed25519PrivateKey, _ = _crypto()
    if not ID_RE.match(a.key_id):
        sys.exit("Schlüssel-Name: a–z, 0–9, _ und -, 2–32 Zeichen")
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"{a.key_id}.key")
    if os.path.exists(path):
        sys.exit(f"{path} gibt es schon – nicht überschreiben (alte Signaturen würden ungültig)")
    key = Ed25519PrivateKey.generate()
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = b64(public_raw(key))
    with open(os.path.join(a.out, f"{a.key_id}.pub"), "w", encoding="utf-8") as f:
        f.write(f"{a.key_id}:{pub}\n")
    print(f"Privater Schlüssel: {path}  (geheim halten, NIE ins Repo)")
    print(f"Öffentlicher Schlüssel für MIRA/PIA (Vertrauenswürdige Herausgeber):\n  {a.key_id}:{pub}")


# ------------------------------------------------------------------ sign / verify
def sign_dir(root: str, key_path: str, key_id: str) -> dict:
    m = load_manifest(root)
    errs = check_manifest(m, {r for r, _ in plugin_files(root)})
    if errs:
        sys.exit("plugin.json fehlerhaft:\n  " + "\n  ".join(errs))
    key = load_key(key_path)
    fp = fingerprint_dir(root)
    sig = {
        "format": FORMAT,
        "key_id": key_id,
        "public_key": b64(public_raw(key)),
        "id": m["id"],
        "version": m["version"],
        "fingerprint": fp,
        "signature": b64(key.sign(signed_message(m["id"], m["version"], fp))),
        "signed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    with open(os.path.join(root, SIGNATURE_FILE), "w", encoding="utf-8", newline="\n") as f:
        json.dump(sig, f, indent=2)
        f.write("\n")
    return sig


def verify_signature(sig: dict, pid: str, version: str, fp: str) -> str:
    """Returns "" if valid, otherwise the reason."""
    _, _, Ed25519PublicKey = _crypto()
    if sig.get("fingerprint") != fp:
        return "Dateien passen nicht zur Signatur (nach dem Signieren geändert)"
    if sig.get("id") not in (None, pid) or sig.get("version") not in (None, version):
        return "Signatur gehört zu einem anderen Plugin/einer anderen Version"
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["public_key"])).verify(
            base64.b64decode(sig["signature"]), signed_message(pid, version, fp))
    except Exception:  # noqa: BLE001
        return "Signatur ungültig"
    return ""


def cmd_sign(a):
    sig = sign_dir(a.dir, a.key, a.key_id)
    print(f"signiert: {sig['id']} {sig['version']} · Schlüssel {sig['key_id']} · Fingerabdruck {sig['fingerprint'][:16]}…")


def read_zip(path: str) -> dict[str, bytes]:
    out = {}
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("zu viele Dateien im Paket")
        total = 0
        for i in infos:
            name = i.filename
            if i.is_dir():
                continue
            if name.startswith("/") or "\\" in name or ".." in name.split("/") or re.match(r"^[A-Za-z]:", name):
                raise ValueError(f"unsicherer Pfad im Paket: {name}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"symbolischer Link im Paket: {name}")
            total += i.file_size
            if total > MAX_UNPACKED:
                raise ValueError("Paket entpackt zu groß")
            out[name] = z.read(i)
    return out


def cmd_verify(a):
    if os.path.isdir(a.target):
        m = load_manifest(a.target)
        files = {r for r, _ in plugin_files(a.target)}
        fp = fingerprint_dir(a.target)
        sig_path = os.path.join(a.target, SIGNATURE_FILE)
        sig = json.load(open(sig_path, encoding="utf-8")) if os.path.exists(sig_path) else None
    else:
        entries = read_zip(a.target)
        if "plugin.json" not in entries:
            sys.exit("plugin.json fehlt im Paket (muss im Hauptordner des ZIP liegen)")
        m = json.loads(entries["plugin.json"])
        files = {k for k in entries if not ignored(k) and k != SIGNATURE_FILE}
        fp = fingerprint_entries([(k, v) for k, v in entries.items() if k in files])
        sig = json.loads(entries[SIGNATURE_FILE]) if SIGNATURE_FILE in entries else None
    errs = check_manifest(m, files)
    print(f"{m.get('id')} {m.get('version')} · {len(files)} Dateien · Fingerabdruck {fp}")
    for e in errs:
        print("  FEHLER:", e)
    if sig is None:
        print("  unsigniert")
    else:
        why = verify_signature(sig, m.get("id", ""), m.get("version", ""), fp)
        print(f"  Signatur {sig.get('key_id')}: {'gültig' if not why else why}  (öffentlicher Schlüssel {sig.get('public_key')})")
        if why:
            errs.append(why)
    sys.exit(1 if errs else 0)


def cmd_check(a):
    m = load_manifest(a.dir)
    errs = check_manifest(m, {r for r, _ in plugin_files(a.dir)})
    for e in errs:
        print("FEHLER:", e)
    if not errs:
        print(f"ok: {m['id']} {m['version']} ({len(plugin_files(a.dir))} Dateien, Fingerabdruck {fingerprint_dir(a.dir)[:16]}…)")
    sys.exit(1 if errs else 0)


# ------------------------------------------------------------------ pack / publish
def pack(root: str, out_dir: str, key: str | None, key_id: str) -> str:
    if key:
        sign_dir(root, key, key_id)
    m = load_manifest(root)
    files = plugin_files(root)
    errs = check_manifest(m, {r for r, _ in files})
    if errs:
        sys.exit("plugin.json fehlerhaft:\n  " + "\n  ".join(errs))
    sig = os.path.join(root, SIGNATURE_FILE)
    if os.path.exists(sig):
        s = json.load(open(sig, encoding="utf-8"))
        if s.get("fingerprint") != fingerprint_dir(root) or s.get("version") != m["version"]:
            sys.exit("signature.json ist veraltet (Dateien oder Version geändert) – mit --key neu signieren oder signature.json löschen")
        files.append((SIGNATURE_FILE, sig))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{m['id']}-{m['version']}.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel, p in sorted(files):
            info = zipfile.ZipInfo(rel, date_time=(2020, 1, 1, 0, 0, 0))   # stable bytes for the same content
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(p, "rb") as f:
                z.writestr(info, f.read())
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def cmd_pack(a):
    path = pack(a.dir, a.out, a.key, a.key_id)
    data = open(path, "rb").read()
    print(f"{path}  ({len(data)} Bytes, sha256 {hashlib.sha256(data).hexdigest()})")


def cmd_publish(a):
    if not a.url or not a.token:
        sys.exit("--url und --token fehlen (oder PIA_URL / PIA_TOKEN setzen)")
    data = open(a.zip, "rb").read()
    url = a.url.rstrip("/") + "/api/v1/plugins" + ("?replace=1" if a.replace else "")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {a.token}", "Content-Type": "application/zip", "Accept": "application/json",
        "User-Agent": "mira-plugin-tool/1"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("detail")
        except Exception:  # noqa: BLE001
            msg = None
        sys.exit(f"Veröffentlichen fehlgeschlagen: {msg or f'HTTP {e.code}'}")
    v = res.get("version", {})
    print(f"veröffentlicht: {res.get('id')} {v.get('version')} · {'signiert (' + v.get('key_id', '') + ')' if v.get('signed') else 'unsigniert'}")


def main():
    ap = argparse.ArgumentParser(description="MIRA-Plugins bauen, signieren und veröffentlichen")
    sub = ap.add_subparsers(dest="cmd", required=True)
    key_default = os.environ.get("MIRA_PLUGIN_KEY")
    key_id_default = os.environ.get("MIRA_PLUGIN_KEY_ID")

    def key_id_of(a):
        if getattr(a, "key", None) and not a.key_id:
            a.key_id = os.path.splitext(os.path.basename(a.key))[0]

    p = sub.add_parser("check", help="plugin.json und Dateien prüfen")
    p.add_argument("dir")
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("keygen", help="Ed25519-Schlüsselpaar für einen Herausgeber erzeugen")
    p.add_argument("key_id")
    p.add_argument("--out", default=".")
    p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("sign", help="signature.json schreiben")
    p.add_argument("dir")
    p.add_argument("--key", default=key_default, required=key_default is None)
    p.add_argument("--key-id", default=key_id_default)
    p.set_defaults(fn=cmd_sign)
    p = sub.add_parser("verify", help="Ordner oder ZIP prüfen (Format + Signatur)")
    p.add_argument("target")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("pack", help="ZIP bauen (mit --key vorher signieren)")
    p.add_argument("dir")
    p.add_argument("--out", default="dist")
    p.add_argument("--key", default=key_default)
    p.add_argument("--key-id", default=key_id_default)
    p.set_defaults(fn=cmd_pack)
    p = sub.add_parser("publish", help="ZIP in ein Plugin-Verzeichnis (PIA) hochladen")
    p.add_argument("zip")
    p.add_argument("--url", default=os.environ.get("PIA_URL"))
    p.add_argument("--token", default=os.environ.get("PIA_TOKEN"))
    p.add_argument("--replace", action="store_true", help="vorhandene gleiche Version ersetzen (nur Admin-Schlüssel)")
    p.set_defaults(fn=cmd_publish)
    a = ap.parse_args()
    key_id_of(a)
    a.fn(a)


if __name__ == "__main__":
    main()
