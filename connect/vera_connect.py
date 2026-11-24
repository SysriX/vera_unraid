#!/usr/bin/env python3
"""VERA-Connect – keeps the WireGuard tunnel of a Windows computer configured, connected and up to date.

    VERA-Connect-Setup.exe                                         install (asks for the address of VERA)
    VERA-Connect-Setup.exe /S URL=https://<VERA_EXTERN> ENROLLKEY=vk_… UPDATEURL=https://<UPDATE_URL> [UPDATEKEY=…] [TUNNEL=…]
    vera-connect.exe install --url … [--enroll-key …] [--update-url …] [--update-key …] [--tunnel …] [--silent]
    vera-connect.exe uninstall | status | version | configure | tray | gui
    vera-connect.exe run [--data DIR] [--simulate]              foreground (the service runs this); --simulate = no WireGuard changes
    vera-connect.exe tunnel list|import FILE|import-qr IMAGE|connect|disconnect|default|rename|delete …   (administrator)
    vera-connect.exe tunnel home NAME on|off [--networks 192.168.99.0/24] [--check host:port]             (administrator)
    vera-connect.exe backup create|list|restore ID|delete ID                                            (administrator)
    vera-connect.exe qr-decode IMAGE                                                                    (any user)

What the service (LocalSystem) does:
  1. device identity: machine id (SMBIOS UUID + MachineGuid + BIOS serial, hashed) and an Ed25519 device key (DPAPI)
  2. POST <VERA>/client/enroll → unknown computers wait in VERA for approval (checks again every minute)
  3. approved → fetch the configuration, keep an encrypted copy, install WireGuard if missing (official MSI, signature checked),
     register the tunnel as a Windows service, switch off WireGuard's own tray/manager
  4. watchdog every 30 s: tunnel missing → restore, no handshake for 3 min → restart (with growing pauses)
  5. VERA changes the configuration (new keys, networks) → new configuration is installed automatically
  6. daily: newer WireGuard → install; every 6 h: newer VERA-Connect in UMA (signed) → update itself
Since 1.2: several tunnels – the one from VERA plus own ones (import of a .conf, a QR code image, by hand, from a backup).
Each can be connected on its own; the default tunnel connects after a restart of Windows. Only one tunnel at a time may take
all traffic (0.0.0.0/0). The window (`gui`) shows every tunnel live (handshake, endpoint, transfer with rate graph) and
manages them; changes go to the service as commands in cmd\\ (administrators only). Backups: tunnels + settings,
sealed with a passphrase, stored in VERA (/client/backup/*), with a list of versions and restore.
Since 1.3: home network detection – a tunnel pauses while an active adapter (not WireGuard) has an address in a network the
tunnel reaches (AllowedIPs or own list) and VERA answers directly through that adapter with its known instance id
(or an own check address answers); it reconnects when the network is left.
The user may disconnect in the tray (the VERA tunnel only if VERA allows it); it stays off until "Verbinden" or the next restart.
Standard library only (+ ed25519.py). Windows: service "VeraConnect", data in C:\\ProgramData\\VERA-Connect.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import ed25519
import netdetect
import wgconf

VERSION = "1.3.2"
PROGRAM = "vera-connect"                         # key of the program in UMA
APP = "VERA-Connect"
SERVICE = "VeraConnect"
WIN = os.name == "nt"
NOWIN = 0x08000000 if WIN else 0
STOP = threading.Event()
COMPILED = "__compiled__" in globals()
SID_SYSTEM, SID_ADMINS, SID_USERS = "*S-1-5-18", "*S-1-5-32-544", "*S-1-5-32-545"
WATCH_EVERY, HANDSHAKE_MAX, WG_CHECK_EVERY, SELF_CHECK_EVERY = 30, 180, 24 * 3600, 6 * 3600
WG_DOWNLOAD = "https://download.wireguard.com/windows-client/"
POLL_MIN = 20
if os.environ.get("VC_FAST"):                                     # tests: seconds instead of minutes/hours
    WATCH_EVERY, SELF_CHECK_EVERY, POLL_MIN = 2, 8, 2


# IPv4 first: many connections have an AAAA record (e.g. dynamic DNS) whose IPv6 path does not reach the proxy.
# Browsers hide that (Happy Eyeballs); Python would wait for the timeout on IPv6. IPv6 stays as fallback.
_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo_v4_first(*args, **kwargs):
    return sorted(_orig_getaddrinfo(*args, **kwargs), key=lambda r: r[0] != socket.AF_INET)


socket.getaddrinfo = _getaddrinfo_v4_first


def default_data() -> str:
    return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), APP)


def home_dir() -> str:
    return os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), APP)


DATA = default_data()
SIMULATE = False


# ------------------------------------------------------------------ log / files
def log(*a) -> None:
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(str(x) for x in a)
    try:
        print(line, flush=True)
    except (OSError, ValueError, AttributeError):
        pass
    try:
        os.makedirs(DATA, exist_ok=True)
        p = os.path.join(DATA, "connect.log")
        if os.path.exists(p) and os.path.getsize(p) > 5 << 20:
            os.replace(p, p + ".1")
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _path(name: str) -> str:
    return os.path.join(DATA, name)


def load(name: str) -> dict:
    try:
        with open(_path(name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


SECRET = ("config.json", "device.json", "state.json")


def _real_install() -> bool:
    return WIN and os.path.normcase(DATA) == os.path.normcase(default_data())


def _lock(path: str) -> None:
    """Readable for SYSTEM and administrators only."""
    if _real_install():
        subprocess.run(["icacls.exe", path, "/inheritance:r", "/grant:r", f"{SID_SYSTEM}:F", f"{SID_ADMINS}:F", "/Q"],
                       stdin=subprocess.DEVNULL, capture_output=True, creationflags=NOWIN)


def save(name: str, data) -> None:
    os.makedirs(DATA, exist_ok=True)
    tmp = _path(name + ".new")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    if name in SECRET:
        _lock(tmp)
    os.replace(tmp, _path(name))


def harden() -> None:
    """Data folder: users may read status + log (tray) and drop flags into ui\\ – nothing else."""
    if not _real_install() or not ctypes.windll.shell32.IsUserAnAdmin():
        return
    os.makedirs(DATA, exist_ok=True)
    subprocess.run(["icacls.exe", DATA, "/inheritance:r", "/grant:r", f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F",
                    f"{SID_USERS}:(OI)(CI)RX", "/Q"], stdin=subprocess.DEVNULL, capture_output=True, creationflags=NOWIN)
    _secure_cmd_dir()
    for sub, users in (("ui", True), ("tunnel", False), ("update", False), ("downloads", False)):
        d = os.path.join(DATA, sub)
        os.makedirs(d, exist_ok=True)
        if users:
            subprocess.run(["icacls.exe", d, "/grant", f"{SID_USERS}:(OI)(CI)M", "/Q"], stdin=subprocess.DEVNULL, capture_output=True, creationflags=NOWIN)
        else:
            _lock(d)
    for f in SECRET:
        if os.path.exists(_path(f)):
            _lock(_path(f))


def run(cmd, timeout: int = 600) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, creationflags=NOWIN)
        raw = r.stdout + b"\n" + r.stderr
        out = raw.decode("utf-16-le", "replace") if b"\x00" in raw[:200] else raw.decode("utf-8", "replace")
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return -1, f"Zeitüberschreitung nach {timeout} s"
    except OSError as e:
        return -1, f"Start fehlgeschlagen: {e}"


def powershell(script: str, timeout: int = 300) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as f:
        f.write("$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding=[Text.Encoding]::UTF8\n" + script)
        p = f.name
    try:
        return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", p], timeout)
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


def spawn_detached(args: list[str] | str, breakaway: bool = True) -> int:
    """Start a process that outlives this one – directly with CreateProcessW and *no* inherited handles.
    subprocess.Popen fails in the service with WinError 6 (it tries to pass on standard handles a service does not
    have). Without breakaway permission (job without JOB_OBJECT_LIMIT_BREAKAWAY_OK) the second try goes without it."""
    if not WIN:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True).pid
    from ctypes import wintypes

    class SI(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class PI(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                                 ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
    cmd = args if isinstance(args, str) else subprocess.list2cmdline(args)
    base = 0x00000008 | 0x00000200 | NOWIN                          # DETACHED_PROCESS, NEW_PROCESS_GROUP, NO_WINDOW
    err = 0
    for flags in ((base | 0x01000000, base) if breakaway else (base,)):  # + CREATE_BREAKAWAY_FROM_JOB
        si, pi = SI(), PI()
        si.cb = ctypes.sizeof(SI)
        buf = ctypes.create_unicode_buffer(cmd)
        if k.CreateProcessW(None, buf, None, None, False, flags, None, None, ctypes.byref(si), ctypes.byref(pi)):
            k.CloseHandle(pi.hThread)
            k.CloseHandle(pi.hProcess)
            return pi.dwProcessId
        err = ctypes.get_last_error()
    raise OSError(err, f"Prozess nicht startbar ({ctypes.FormatError(err).strip()}): {cmd[:200]}")


# ------------------------------------------------------------------ DPAPI (keys and cached configuration)
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if not WIN:
        return data
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    src, dst = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), "VERA-Connect" if protect else None, None, None, None, 0x1, ctypes.byref(dst))   # UI_FORBIDDEN
    if not ok:
        raise OSError(f"DPAPI fehlgeschlagen ({ctypes.GetLastError()})")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        kernel32.LocalFree(dst.pbData)


def protect(b: bytes) -> str:
    return base64.b64encode(_dpapi(b, True)).decode()


def unprotect(s: str) -> bytes:
    return _dpapi(base64.b64decode(s), False)


# ------------------------------------------------------------------ identity
def machine_facts() -> dict:
    if not WIN:
        return {"uuid": "", "guid": socket.gethostname(), "serial": "", "hostname": socket.gethostname(), "domain": "",
                "user": os.environ.get("USER", ""), "os": platform.platform()}
    c, o = powershell(r"""
$p = Get-CimInstance Win32_ComputerSystemProduct; $b = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$u = $cs.UserName
if (-not $u) { $e = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
  if ($e) { $o = Invoke-CimMethod -InputObject $e -MethodName GetOwner; if ($o.User) { $u = "$($o.Domain)\$($o.User)" } } }
[pscustomobject]@{uuid=$p.UUID; guid=$g; serial=$b.SerialNumber; hostname=$env:COMPUTERNAME; domain=$(if ($cs.PartOfDomain) { $cs.Domain } else { "" })
  user=$u; os="$($os.Caption) $($os.Version)"} | ConvertTo-Json -Compress
""", 120)
    try:
        return json.loads(o[o.index("{"):])
    except ValueError:
        log("Rechnerdaten nicht lesbar:", o[-300:])
        return {"uuid": "", "guid": "", "serial": "", "hostname": os.environ.get("COMPUTERNAME", ""), "domain": "", "user": "", "os": platform.platform()}


def compute_machine_id(f: dict) -> str:
    raw = "|".join(str(f.get(k) or "").strip().upper() for k in ("uuid", "guid", "serial"))
    return hashlib.sha256(("vera-connect|" + raw).encode()).hexdigest()


class Device:
    """Machine id + Ed25519 key. A different machine id (new hardware, cloned disk) creates a new key → VERA asks again."""

    def __init__(self):
        self.facts = machine_facts()
        self.facts_at = time.time()
        mid = compute_machine_id(self.facts)
        d = load("device.json")
        if d.get("machine_id") != mid or not d.get("key"):
            if d.get("machine_id"):
                log("Rechner-Kennung hat sich geändert (neue Hardware oder geklonter Datenträger) – neuer Geräteschlüssel, VERA fragt neu nach")
            d = {"machine_id": mid, "key": protect(ed25519.new_secret()), "created": time.time()}
            save("device.json", d)
        self.machine_id = mid
        self._secret = unprotect(d["key"])
        self.public = base64.b64encode(ed25519.public_key(self._secret)).decode()

    def refresh_facts(self) -> dict:
        if time.time() - self.facts_at > 900:
            self.facts, self.facts_at = machine_facts(), time.time()
        return self.facts

    def headers(self, method: str, path: str, body: bytes) -> dict:
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        msg = f"{method}\n{path}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
        return {"X-Device": self.machine_id, "X-Time": ts, "X-Nonce": nonce,
                "X-Signature": base64.b64encode(ed25519.sign(self._secret, msg)).decode()}


class HttpError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Python 3.13 trusts any certificate in the store as anchor (PARTIAL_CHAIN). Switched off: an intermediate fetched
    # via AIA must still chain up to a root of Windows – it only fills a gap, it never becomes trusted by itself.
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


_ssl = _tls_context()
_aia_tried: set[str] = set()


def _load_extra_ca() -> None:
    p = os.path.join(DATA, "ca-extra.pem")
    if os.path.exists(p):
        try:
            _ssl.load_verify_locations(cafile=p)
        except (OSError, ssl.SSLError) as e:
            log("ca-extra.pem nicht lesbar:", e)


def _aia_issuer_url(der: bytes) -> str | None:
    """URL of the issuing certificate (Authority Information Access, id-ad-caIssuers) inside a DER certificate."""
    oid = bytes.fromhex("06082b06010505073002")
    i = der.find(oid)
    if i < 0:
        return None
    j = i + len(oid)
    if j + 2 > len(der) or der[j] != 0x86:
        return None
    ln, k = der[j + 1], j + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln, k = int.from_bytes(der[k:k + n], "big"), k + n
    url = der[k:k + ln].decode("ascii", "replace")
    return url if url.startswith(("http://", "https://")) else None


def _cert_names(pem: str) -> tuple:
    """(subject, issuer) of a PEM certificate – standard library only."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(pem)
        d = ssl._ssl._test_decode_cert(path)                        # noqa: SLF001 – the only stdlib X.509 parser
        return d.get("subject"), d.get("issuer")
    finally:
        os.remove(path)


def windows_chain(der: bytes, host: str) -> list[str]:
    """Ask the Windows certificate engine (the one browsers use) to build the chain for the server certificate.
    Windows fetches missing intermediates and – if needed – the root via its automatic root update, which a service
    using OpenSSL never triggers. Only if Windows reports the chain as trusted are its certificates (intermediates and
    root) handed to OpenSSL; the host name is still checked by Python afterwards."""
    if not WIN or not der:
        return []
    fd, path = tempfile.mkstemp(suffix=".cer")
    with os.fdopen(fd, "wb") as f:
        f.write(der)
    try:
        c, out = powershell(f"""
$c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 '{path}'
$ch = New-Object Security.Cryptography.X509Certificates.X509Chain
$ch.ChainPolicy.RevocationMode = 'NoCheck'
$ch.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
$ok = $ch.Build($c)
"OK=$ok"
$ch.ChainElements | Select-Object -Skip 1 | ForEach-Object {{ 'CERT=' + [Convert]::ToBase64String($_.Certificate.RawData) }}
$ch.ChainStatus | ForEach-Object {{ 'STATUS=' + $_.Status + ' ' + ($_.StatusInformation -replace '\\s+', ' ') }}
""", 120)
    finally:
        os.remove(path)
    lines = out.splitlines()
    if "OK=True" not in lines:
        log(f"Windows vertraut dem Zertifikat von {host} nicht:", "; ".join(x[7:] for x in lines if x.startswith("STATUS="))[:300] or out[-300:])
        return []
    return [ssl.DER_cert_to_PEM_cert(base64.b64decode(x[5:])) for x in lines if x.startswith("CERT=")]


def fetch_missing_intermediate(url: str) -> bool:
    """The server sends only its own certificate (chain incomplete). Browsers fill the gap themselves – we do the same:
    follow the issuer addresses (AIA) upwards, at most 4 steps, and load the intermediates. A self-signed root found
    on the way is never loaded: the chain must still end at a root that Windows already trusts."""
    from urllib.parse import urlsplit
    u = urlsplit(url)
    host, port = u.hostname, u.port or 443
    if not host or host in _aia_tried:
        return False
    _aia_tried.add(host)
    raw = ssl.create_default_context()
    raw.check_hostname, raw.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as sock, raw.wrap_socket(sock, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True) or b""
    loaded = []
    for pem in windows_chain(der, host):                            # first: let Windows decide (like the browser)
        _ssl.load_verify_locations(cadata=pem)
        loaded.append(("Windows", pem))
    for _ in range(0 if loaded else 4):
        issuer = _aia_issuer_url(der)
        if not issuer:
            break
        with urllib.request.urlopen(urllib.request.Request(issuer, headers={"User-Agent": f"{APP}/{VERSION}"}), timeout=20) as r:
            data = r.read(200_000)
        pem = data.decode("ascii", "replace") if data.lstrip().startswith(b"-----BEGIN") else ssl.DER_cert_to_PEM_cert(data)
        subj, iss = _cert_names(pem)
        if subj == iss:                                             # a root – never trusted from the network
            break
        _ssl.load_verify_locations(cadata=pem)
        loaded.append((issuer, pem))
        der = ssl.PEM_cert_to_DER_cert(pem)
    if not loaded:
        return False
    try:
        os.makedirs(DATA, exist_ok=True)
        cache = os.path.join(DATA, "ca-extra.pem")
        have = open(cache, encoding="ascii").read() if os.path.exists(cache) else ""
        with open(cache, "a", encoding="ascii") as f:
            for _, pem in loaded:
                if pem.strip() not in have:                         # no duplicates
                    f.write(pem.strip() + "\n")
    except OSError:
        pass
    log(f"{host} schickt die Zertifikatskette unvollständig – {len(loaded)} Zwischenzertifikat(e) nachgeladen "
        f"({', '.join(x for x, _ in loaded)}). Besser: am Server/Reverse-Proxy die vollständige Kette (fullchain) eintragen.")
    return True


def _is_chain_error(e: BaseException) -> bool:
    r = getattr(e, "reason", e)
    return isinstance(r, ssl.SSLCertVerificationError) and getattr(r, "verify_code", 0) in (2, 20, 21)   # unable to get (local) issuer


def explain(e: BaseException) -> str:
    """Short German reason for the tray/log instead of only "not reachable"."""
    r = getattr(e, "reason", e)
    if isinstance(r, ssl.SSLCertVerificationError):
        return f"Zertifikat von VERA nicht prüfbar ({r.verify_message})"
    if isinstance(r, ssl.SSLError):
        return f"TLS-Fehler ({r})"
    if isinstance(r, socket.gaierror):
        return "Name von VERA nicht auflösbar (DNS)"
    if isinstance(r, (TimeoutError, socket.timeout)):
        return "Zeitüberschreitung – Port gesperrt oder Weiterleitung fehlt?"
    if isinstance(r, ConnectionRefusedError):
        return "Verbindung abgelehnt"
    if isinstance(e, ValueError):
        return "VERA antwortet nicht wie erwartet (Anmeldeseite oder Proxy davor?)"
    return str(r)[:200]


def request(dev: Device, base: str, method: str, path: str, data: dict | None = None, raw: bool = False, timeout: int = 30):
    """Signed request. path without host (signature covers it); base may carry a sub-path (https://host/vera)."""
    from urllib.parse import urlsplit
    full = base.rstrip("/") + path
    body = json.dumps(data).encode() if data is not None else b""
    req = urllib.request.Request(full, data=body if method != "GET" else None, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": f"{APP}/{VERSION}",
                                          **dev.headers(method, urlsplit(full).path, body)})
    try:
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl) as r:
                b = r.read()
        except urllib.error.URLError as e:
            if isinstance(e, urllib.error.HTTPError) or not _is_chain_error(e) or not fetch_missing_intermediate(full):
                raise
            req = urllib.request.Request(full, data=body if method != "GET" else None, method=method,
                                         headers={"Content-Type": "application/json", "User-Agent": f"{APP}/{VERSION}",
                                                  **dev.headers(method, urlsplit(full).path, body)})
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl) as r:
                b = r.read()
        return b if raw else json.loads(b or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}").get("detail") or e.reason
        except (ValueError, AttributeError):
            detail = e.reason
        raise HttpError(e.code, str(detail)) from e


# ------------------------------------------------------------------ status for the tray
STATUS: dict = {"state": "start"}


def set_status(**kw) -> None:
    STATUS.update(kw, version=VERSION, updated=time.time(), pid=os.getpid())
    try:
        os.makedirs(DATA, exist_ok=True)
        tmp = _path("status.json.new")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(STATUS, f, ensure_ascii=False)
        os.replace(tmp, _path("status.json"))
    except OSError:
        pass


def take_flag(name: str) -> bool:
    p = os.path.join(DATA, "ui", name)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass
        return True
    return False


# ------------------------------------------------------------------ WireGuard
def arch() -> tuple[str, str]:
    """(UMA arch, WireGuard MSI arch)"""
    a = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64").upper()
    return ("arm64", "arm64") if "ARM" in a else ("x64", "amd64") if "64" in a else ("x86", "x86")


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


class WireGuard:
    def __init__(self):
        base = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WireGuard")
        self.exe, self.wg = os.path.join(base, "wireguard.exe"), os.path.join(base, "wg.exe")
        self._sim: dict[str, str] = {}                     # simulation: tunnel -> RUNNING | STOPPED
        self._simc: dict[str, list] = {}

    def installed(self) -> bool:
        return bool(STATUS.get("sim_wg")) if SIMULATE else os.path.exists(self.exe)

    def version(self) -> str:
        if SIMULATE:
            return STATUS.get("sim_wg", "")
        if not os.path.exists(self.exe):
            return ""
        import winreg
        for root in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",):
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            except OSError:
                continue
            for i in range(10000):
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                try:
                    s = winreg.OpenKey(k, sub)
                    if str(winreg.QueryValueEx(s, "DisplayName")[0]).startswith("WireGuard"):
                        return str(winreg.QueryValueEx(s, "DisplayVersion")[0])
                except OSError:
                    continue
        return "?"

    @staticmethod
    def latest() -> tuple[str, str]:
        """(version, url) of the newest official MSI for this computer."""
        with urllib.request.urlopen(urllib.request.Request(WG_DOWNLOAD, headers={"User-Agent": f"{APP}/{VERSION}"}),
                                    timeout=30, context=_ssl) as r:
            html = r.read().decode("utf-8", "replace")
        _, msi_arch = arch()
        vers = sorted(set(re.findall(rf"wireguard-{msi_arch}-(\d+(?:\.\d+)+)\.msi", html)), key=vkey)
        if not vers:
            raise RuntimeError("Keine WireGuard-Version auf download.wireguard.com gefunden")
        return vers[-1], f"{WG_DOWNLOAD}wireguard-{msi_arch}-{vers[-1]}.msi"

    def install(self, version: str, url: str) -> None:
        """Download the official MSI from the vendor and install it (fallback when UMA does not offer WireGuard)."""
        if SIMULATE:
            log("[simuliert] WireGuard", version, "vom Hersteller installieren")
            STATUS["sim_wg"] = version
            return
        d = os.path.join(DATA, "downloads")
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, url.rsplit("/", 1)[-1])
        log("Lade WireGuard", version, "vom Hersteller …")
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": f"{APP}/{VERSION}"}), timeout=300, context=_ssl) as r, \
                open(f, "wb") as out:
            shutil.copyfileobj(r, out)
        self.install_file(version, f)

    def install_file(self, version: str, f: str) -> None:
        """Check the Authenticode signature (WireGuard LLC) of the MSI and install it silently."""
        if SIMULATE:
            log("[simuliert] WireGuard", version, "aus", os.path.basename(f), "installieren")
            STATUS["sim_wg"] = version
            return
        c, o = powershell(f"$s = Get-AuthenticodeSignature -LiteralPath '{f}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\"", 120)
        if not o.startswith("Valid|") or "WireGuard LLC" not in o:
            os.remove(f)
            raise RuntimeError(f"Signatur des WireGuard-Pakets ungültig: {o[-200:]}")
        c, o = run(["msiexec.exe", "/i", f, "/qn", "/norestart", "DO_NOT_LAUNCH=1"], 900)
        try:
            os.remove(f)
        except OSError:
            pass
        if c not in (0, 3010):
            raise RuntimeError(f"WireGuard-Installation fehlgeschlagen (Code {c}): {o[-300:]}")
        log("WireGuard", version, "installiert")
        self.disable_manager()

    def disable_manager(self) -> None:
        """WireGuard's own tray/manager is not needed – VERA-Connect does its job. Tunnel services keep running."""
        if SIMULATE or not os.path.exists(self.exe):
            return
        c, o = run(["sc.exe", "query", "WireGuardManager"], 30)
        if c == 0:
            run([self.exe, "/uninstallmanagerservice"], 60)
            log("WireGuard-Manager (Tray) abgeschaltet")

    @staticmethod
    def service(name: str) -> str:
        return f"WireGuardTunnel${name}"

    def svc_state(self, name: str) -> str:
        if SIMULATE:
            return self._sim.get(name, "MISSING")
        c, o = run(["sc.exe", "query", self.service(name)], 30)
        m = re.search(r":\s*\d\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING)", o)
        return m.group(1) if m else "MISSING"

    def conf_path(self, name: str) -> str:
        return os.path.join(DATA, "tunnel", f"{name}.conf")

    def install_tunnel(self, name: str, text: str) -> None:
        p = self.conf_path(name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if self.svc_state(name) != "MISSING":
            self.remove_tunnel(name)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        _lock(p)
        if SIMULATE:
            self._sim[name] = "RUNNING"
            log("[simuliert] Tunnel", name, "eingerichtet")
            return
        c, o = run([self.exe, "/installtunnelservice", p], 120)
        if c != 0:
            raise RuntimeError(f"Tunnel einrichten fehlgeschlagen ({c}): {o[-300:]}")
        log("Tunnel", name, "eingerichtet")

    def remove_tunnel(self, name: str) -> None:
        if SIMULATE:
            self._sim.pop(name, None)
        elif self.svc_state(name) != "MISSING":
            run([self.exe, "/uninstalltunnelservice", name], 120)
            for _ in range(20):
                if self.svc_state(name) == "MISSING":
                    break
                time.sleep(1)
        try:
            os.remove(self.conf_path(name))
        except OSError:
            pass

    def start(self, name: str) -> None:
        if SIMULATE:
            if name in self._sim:
                self._sim[name] = "RUNNING"
            return
        run(["sc.exe", "start", self.service(name)], 60)

    def stop(self, name: str) -> None:
        if SIMULATE:
            if name in self._sim:
                self._sim[name] = "STOPPED"
            return
        run(["sc.exe", "stop", self.service(name)], 60)

    def dump(self) -> dict:
        """All running tunnels at once (`wg show all dump`): name -> {listen_port, peers, rx, tx, last_handshake, endpoint}."""
        out: dict = {}
        if SIMULATE:
            import random
            for n, s in self._sim.items():
                if s != "RUNNING":
                    continue
                c = self._simc.setdefault(n, [0, 0])
                c[0] += random.randint(2_000, 400_000)
                c[1] += random.randint(500, 60_000)
                out[n] = {"listen_port": "51820", "peers": [{"public_key": "SIM", "endpoint": "198.51.100.7:51820",
                                                               "allowed_ips": "10.0.0.0/24", "last_handshake": int(time.time()) - 20,
                                                               "rx": c[0], "tx": c[1]}]}
        else:
            if not os.path.exists(self.wg):
                return {}
            c, o = run([self.wg, "show", "all", "dump"], 30)
            if c != 0:
                return {}
            for line in o.splitlines():
                p = line.split("\t")
                if len(p) == 5:
                    out[p[0]] = {"listen_port": p[3], "peers": []}
                elif len(p) >= 9 and p[0] in out:
                    try:
                        out[p[0]]["peers"].append({"public_key": p[1], "endpoint": "" if p[3] == "(none)" else p[3],
                                                   "allowed_ips": p[4], "last_handshake": int(p[5]), "rx": int(p[6]), "tx": int(p[7])})
                    except ValueError:
                        continue
        for v in out.values():
            ps = v["peers"]
            v.update(rx=sum(x["rx"] for x in ps), tx=sum(x["tx"] for x in ps),
                     last_handshake=max((x["last_handshake"] for x in ps), default=0),
                     endpoint=next((x["endpoint"] for x in ps if x["endpoint"]), ""))
        return out

    def stats(self, name: str) -> dict:
        """latest handshake (unix time) and transfer of one tunnel."""
        d = self.dump().get(name) or {}
        return {k: d[k] for k in ("last_handshake", "rx", "tx") if k in d}


# ------------------------------------------------------------------ the service loop
def boot_time() -> int:
    if WIN:
        return int(time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000) // 60 * 60
    return 0


class CmdError(Exception):
    pass


CMD_DIR = "cmd"


def _secure_cmd_dir() -> str:
    """Folder for commands of the window/CLI: only SYSTEM and administrators may write (and read – may contain keys)."""
    d = os.path.join(DATA, CMD_DIR)
    os.makedirs(d, exist_ok=True)
    if _real_install():
        subprocess.run(["icacls.exe", d, "/inheritance:r", "/grant:r", f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F", "/Q"],
                       stdin=subprocess.DEVNULL, capture_output=True, creationflags=NOWIN)
    return d


class Agent:
    def __init__(self):
        _load_extra_ca()
        self.dev = Device()
        self.wg = WireGuard()
        self.state = load("state.json")
        self.events: list[str] = []
        self.next_poll = self.next_wg = self.next_self = 0.0
        self.uma_wg = None
        self.rt: dict[str, dict] = {}                       # per tunnel: started, pause, next_restart
        self._summaries: dict[str, tuple] = {}
        self.home_cache: dict[str, dict] = {}
        self._local: list = []
        self.net_fp, self.next_net, self._inst_t = None, 0.0, 0.0
        self.state.setdefault("local", {})
        self.state.setdefault("home", {})
        if self.state.get("user_off") is None:
            self.state["user_off"] = False
        boot = boot_time()
        if self.state.get("boot", self.state.get("user_off_boot")) != boot:
            self.boot_policy()
        self.state["boot"] = boot
        self.keep()
        try:
            os.makedirs(os.path.join(DATA, "ui"), exist_ok=True)
            _secure_cmd_dir()
        except OSError as e:
            log("Befehlsordner:", e)

    # ----- helpers
    @property
    def conf(self) -> dict:
        return load("config.json")

    def event(self, text: str) -> None:
        log(text)
        self.events = (self.events + [text])[-10:]

    def keep(self) -> None:
        save("state.json", self.state)

    def cached_config(self) -> str:
        try:
            return unprotect(self.state["config"]).decode() if self.state.get("config") else ""
        except OSError:
            return ""

    # ----- tunnels: the one from VERA + own ones (imported, QR, created by hand, restored)
    @property
    def local(self) -> dict:
        return self.state["local"]

    def vera_name(self) -> str | None:
        return self.state.get("tunnel")

    def names(self) -> list[str]:
        return ([self.vera_name()] if self.vera_name() else []) + sorted(self.local, key=str.lower)

    def find(self, name: str) -> str | None:
        return next((n for n in self.names() if n.lower() == (name or "").lower()), None)

    def default_name(self) -> str | None:
        d = self.state.get("default")
        if d and d in self.names():
            return d
        return self.vera_name() or (self.names() or [None])[0]

    def is_on(self, name: str) -> bool:
        if name == self.vera_name():
            return not self.state.get("user_off")
        return bool(self.local.get(name, {}).get("on"))

    def config_of(self, name: str) -> str:
        if name == self.vera_name():
            return self.cached_config()
        t = self.local.get(name)
        try:
            return unprotect(t["config"]).decode() if t and t.get("config") else ""
        except OSError:
            return ""

    def summary(self, name: str) -> dict:
        text = self.config_of(name)
        h = hashlib.sha256(text.encode()).hexdigest()
        if self._summaries.get(name, ("",))[0] != h:
            try:
                s = wgconf.summary(text) if text else {}
            except wgconf.ConfError:
                s = {}
            self._summaries[name] = (h, s)
        return self._summaries[name][1]

    def boot_policy(self) -> None:
        """After a restart of Windows only the default tunnel connects (the VERA tunnel also if VERA forbids disconnecting)."""
        d = self.default_name()
        for n, t in self.local.items():
            t["on"] = n == d
        if self.vera_name():
            self.state["user_off"] = not (d == self.vera_name() or not self.state.get("allow_disconnect", True))
        if self.names():
            log(f"Windows neu gestartet – verbunden wird der Standard-Tunnel {d}")

    def allow_disconnect(self) -> bool:
        return bool(STATUS.get("allow_disconnect", self.state.get("allow_disconnect", True)))

    def set_on(self, name: str, on: bool, who: str = "Benutzer") -> None:
        name = self.find(name) or name
        if name not in self.names():
            raise CmdError(f"Tunnel „{name}“ gibt es nicht")
        if self.is_on(name) == on:
            return
        vt = self.vera_name()
        if not on and name == vt and not self.allow_disconnect():
            raise CmdError("Den Tunnel von VERA zu trennen ist in VERA nicht erlaubt")
        if on and self.summary(name).get("full_tunnel"):            # only one tunnel may take all traffic
            for other in self.names():
                if other != name and self.is_on(other) and self.summary(other).get("full_tunnel"):
                    if other == vt and not self.allow_disconnect():
                        raise CmdError(f"„{other}“ leitet schon den ganzen Verkehr um und darf nicht getrennt werden")
                    self.set_on(other, False, who)
                    self.event(f"Tunnel {other} getrennt – {name} leitet den ganzen Verkehr um")
        if name == vt:
            self.state["user_off"] = not on
        else:
            self.local[name]["on"] = on
        self.keep()
        self.rt.pop(name, None)
        if not on and self.wg.svc_state(name) != "MISSING":
            self.wg.remove_tunnel(name)
        self.event(f"Tunnel {name} {'verbunden' if on else 'getrennt'} ({who})")

    def rows(self, dump: dict) -> list[dict]:
        d = self.default_name()
        out = []
        for n in self.names():
            s = self.summary(n)
            live = dump.get(n) or {}
            peers = s.get("peers") or [{}]
            out.append({"name": n, "source": "vera" if n == self.vera_name() else "local", "on": self.is_on(n), "default": n == d,
                        "state": self.rt.get(n, {}).get("state", "off"), "address": ", ".join(s.get("address", [])),
                        "dns": ", ".join(s.get("dns", [])), "endpoint": live.get("endpoint") or peers[0].get("endpoint", ""),
                        "allowed_ips": ", ".join(a for p in s.get("peers", []) for a in p["allowed_ips"]),
                        "public_key": s.get("public_key", ""), "full_tunnel": bool(s.get("full_tunnel")),
                        "last_handshake": live.get("last_handshake", 0), "origin": self.local.get(n, {}).get("origin", "VERA"),
                        "home": self.home_cfg(n), "home_networks": [str(x) for x in self.home_networks(n)],
                        "home_why": self.rt.get(n, {}).get("home_why", "")})
        return out

    def report(self) -> dict:
        f = self.dev.refresh_facts()
        st = {"version": VERSION, "wg_version": self.wg.version(), "wg_source": STATUS.get("wg_source", ""), "hostname": f.get("hostname"), "user": f.get("user") or "",
              "os": f.get("os"), "user_off": bool(self.state.get("user_off")), "tunnel_state": STATUS.get("tunnel_state", "waiting"),
              "tunnels": [{"name": r["name"], "source": r["source"], "on": r["on"], "state": r["state"], "default": r["default"]}
                          for r in STATUS.get("tunnels", [])][:20]}
        t = self.vera_name()
        if t and STATUS.get("tunnel_state") == "up":
            st.update(self.wg.stats(t))
        if STATUS.get("last_error"):
            st["error"] = STATUS["last_error"][:300]
        return st

    # ----- VERA
    def enroll(self) -> dict:
        c, f = self.conf, self.dev.refresh_facts()
        r = request(self.dev, c["url"], "POST", "/client/enroll",
                    {"machine_id": self.dev.machine_id, "public_key": self.dev.public, "hostname": f.get("hostname"),
                     "domain": f.get("domain"), "user": f.get("user"), "os": f.get("os"), "version": VERSION,
                     "enroll_key": c.get("enroll_key", "")})
        self.state["enrolled"] = c["url"]
        self.keep()
        log("Bei VERA angemeldet – Status:", r.get("status"))
        return r

    def poll(self) -> None:
        c = self.conf
        if not c.get("url"):
            set_status(state="no_url", message="Adresse von VERA fehlt – Einstellungen öffnen")
            self.next_poll = time.time() + 60
            return
        try:
            if self.state.get("enrolled") != c["url"]:
                self.enroll()
            try:
                r = request(self.dev, c["url"], "POST", "/client/poll",
                            {"config_hash": self.state.get("config_hash", ""), "report": self.report(), "events": self.events})
            except HttpError as e:
                if e.status != 404:
                    raise
                self.enroll()
                r = request(self.dev, c["url"], "POST", "/client/poll",
                            {"config_hash": self.state.get("config_hash", ""), "report": self.report(), "events": self.events})
            self.events = []
            STATUS.pop("last_error", None)
            allow = bool(r.get("allow_disconnect", True))
            if self.state.get("allow_disconnect", True) != allow:
                self.state["allow_disconnect"] = allow
                self.keep()
            set_status(server_ok=time.time(), allow_disconnect=allow, vera=c["url"], backup=bool(r.get("backup")))
            self.learn_instance(c["url"])
            self.next_poll = time.time() + (POLL_MIN if os.environ.get("VC_FAST") else max(POLL_MIN, int(r.get("interval") or 60)))
            st = r.get("status")
            if st == "pending":
                set_status(state="pending", message="wartet auf Freigabe in VERA")
            elif st == "blocked":
                if self.vera_name():
                    self.wg.remove_tunnel(self.vera_name())
                    self.event("In VERA gesperrt – Tunnel entfernt")
                    if self.state.get("default") == self.vera_name():
                        self.state["default"] = None
                self.state.update(tunnel=None, config=None, config_hash="")
                self.keep()
                set_status(state="blocked", message="in VERA gesperrt", tunnel_state="missing")
            elif st == "no_config":
                set_status(state="error", message=r.get("message") or "keine Konfiguration")
            elif st == "approved":
                if r.get("config_hash") and r["config_hash"] != self.state.get("config_hash"):
                    self.fetch_and_apply()
                elif STATUS.get("state") in ("pending", "start", "no_url", "offline", "error", "blocked"):
                    set_status(state="ready", message="")
        except HttpError as e:
            set_status(state="error" if e.status != 403 else "denied", message=e.detail, last_error=str(e))
            log("VERA:", e)
            self.next_poll = time.time() + 120
        except (OSError, ValueError) as e:                       # offline: keep using the cached configuration
            why = explain(e)
            set_status(state="offline" if not self.state.get("config") else STATUS.get("state", "offline"),
                       message=f"VERA nicht erreichbar: {why}" + (" – letzte Konfiguration bleibt aktiv" if self.state.get("config") else ""),
                       last_error=why)
            log("VERA nicht erreichbar:", why, "|", repr(e)[:300])
            self.next_poll = time.time() + 120

    def learn_instance(self, url: str) -> None:
        """Instance id of VERA (/.well-known/sysrix-app) – proves later that the VERA in a local network is ours."""
        if time.time() - self._inst_t < 3600 and self.state.get("vera_instance"):
            return
        self._inst_t = time.time()
        try:
            with urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + "/.well-known/sysrix-app",
                                                               headers={"User-Agent": f"{APP}/{VERSION}"}), timeout=15, context=_ssl) as r:
                inst = json.loads(r.read(4000)).get("instance")
            if inst and inst != self.state.get("vera_instance"):
                self.state["vera_instance"] = inst
                self.keep()
        except (OSError, ValueError) as e:
            log("Kennung von VERA nicht lesbar:", e)

    # ----- home network detection
    def home_cfg(self, name: str) -> dict:
        c = self.state["home"].get(name) or {}
        return {"enabled": c.get("enabled", True), "networks": list(c.get("networks") or []), "check": c.get("check") or ""}

    def tunnel_ips(self) -> set:
        return {a.split("/")[0] for n in self.names() for a in self.summary(n).get("address", [])}

    def refresh_local(self) -> bool:
        """Addresses of the active adapters; True if they changed since the last look."""
        try:
            self._local = netdetect.local_ipv4(self.tunnel_ips(), DATA if SIMULATE else None)
        except Exception as e:  # noqa: BLE001
            log("Netzwerkadapter nicht lesbar:", e)
            self._local = []
        fp = tuple(sorted((ip, pre) for ip, pre, _ in self._local))
        changed = fp != self.net_fp
        if changed and self.net_fp is not None:
            log("Netzwerk geändert:", ", ".join(f"{ip}/{pre}" for ip, pre in fp) or "keine Adresse")
        self.net_fp = fp
        return changed

    def home_networks(self, name: str) -> list:
        return netdetect.networks_of(self.summary(name), self.home_cfg(name)["networks"])

    def at_home(self, name: str) -> tuple[bool, str]:
        cfg = self.home_cfg(name)
        if not cfg["enabled"]:
            return False, ""
        nets = self.home_networks(name)
        m = netdetect.match(self._local, nets) if nets else None
        if not m:
            self.home_cache.pop(name, None)
            return False, ""
        key = (m[0], str(m[1]), cfg["check"], self.conf.get("url"), self.state.get("vera_instance"))
        c = self.home_cache.get(name)
        if c and c["key"] == key and time.time() - c["t"] < (600 if c["home"] else 120):
            return c["home"], c["why"]
        home, why = self.verify_home(m[0], nets, cfg["check"])
        self.home_cache[name] = {"key": key, "t": time.time(), "home": home, "why": why}
        if not home:
            log(f"Tunnel {name}: Adresse {m[0]} liegt in {m[1]}, aber kein Heimnetz – {why}")
        return home, why

    def verify_home(self, local_ip: str, nets: list, check: str) -> tuple[bool, str]:
        """Is the check address (default: VERA) reachable directly through the local adapter? Its address must lie in
        one of the tunnel networks – a public address would also answer from any hotel network."""
        import ipaddress
        if check:
            u = urlsplit(check if "://" in check else "tcp://" + check)
            host, port = u.hostname or "", u.port or 443
            addrs = netdetect.resolve4(host)
            if not any(ipaddress.ip_address(a) in n for a in addrs for n in nets):
                return False, f"Prüfadresse {host} liegt nicht in den Heimnetzen"
            ok = netdetect.probe_tcp(host, port, local_ip)
            return ok, f"{host}:{port} direkt erreichbar über {local_ip}" if ok else f"{host}:{port} über {local_ip} nicht erreichbar"
        url = self.conf.get("url") or ""
        host = urlsplit(url).hostname or ""
        if not host:
            return False, "Adresse von VERA fehlt"
        inst = self.state.get("vera_instance")
        if not inst:
            return False, "Kennung von VERA noch unbekannt"
        addrs = netdetect.resolve4(host)
        if not any(ipaddress.ip_address(a) in n for a in addrs for n in nets):
            return False, f"VERA ({host} → {', '.join(addrs) or '?'}) liegt nicht in den Heimnetzen"
        d = netdetect.probe_vera(url, local_ip, _ssl)
        if not d:
            return False, f"VERA über {local_ip} nicht erreichbar"
        if d.get("instance") != inst:
            return False, "dort antwortet ein anderes VERA"
        return True, f"VERA direkt erreichbar über {local_ip}"

    def fetch_and_apply(self) -> None:
        r = request(self.dev, self.conf["url"], "POST", "/client/config", {})
        name = wgconf.safe_name(self.conf.get("tunnel") or r.get("tunnel") or "VERA", "VERA")
        if any(n.lower() == name.lower() for n in self.local):        # name taken by an own tunnel
            name = (name[:27] + "-VERA")
        text = r["text"]
        self.ensure_wireguard()
        old = self.vera_name()
        if old and old != name:
            self.wg.remove_tunnel(old)
            if self.state.get("default") == old:
                self.state["default"] = name
        if not self.vera_name() and not self.state.get("default"):
            self.state["default"] = name
        self.state.update(tunnel=name, config=protect(text.encode()), config_hash=r["hash"])
        self.keep()
        self.rt.pop(name, None)
        if self.is_on(name):
            self.wg.install_tunnel(name, text)
            self.rt[name] = {"started": time.time(), "pause": 60, "next": 0, "state": "connecting"}
        elif self.wg.svc_state(name) != "MISSING":
            self.wg.remove_tunnel(name)
        self.event(f"Neue Konfiguration von VERA eingerichtet (Tunnel {name})")
        set_status(state="ready", message="", tunnel=name)

    # ----- UMA: own updates + components (WireGuard)
    def uma_base(self) -> str:
        return (self.conf.get("update_url") or "").rstrip("/")

    def uma_check(self) -> dict | None:
        """Ask UMA for a newer VERA-Connect and the components (WireGuard). None = no UMA configured."""
        base = self.uma_base()
        if not base:
            return None
        c = self.conf
        if not c.get("update_key"):                              # pin the key of this UMA on first contact
            try:
                with urllib.request.urlopen(base + "/u/info", timeout=30, context=_ssl) as r:
                    info = r.read()
            except urllib.error.URLError as e:
                if isinstance(e, urllib.error.HTTPError) or not _is_chain_error(e) or not fetch_missing_intermediate(base):
                    raise
                with urllib.request.urlopen(base + "/u/info", timeout=30, context=_ssl) as r:
                    info = r.read()
            c["update_key"] = json.loads(info)["public_key"]
            save("config.json", c)
            log("Signaturschlüssel des Update-Servers gemerkt:", c["update_key"][:16] + "…")
        f, uma_arch = self.dev.refresh_facts(), arch()[0]
        wgv = self.wg.version() if self.wg.installed() else ""
        r = request(self.dev, base, "POST", "/u/check", {"program": PROGRAM, "version": VERSION, "arch": uma_arch,
                                                          "machine_id": self.dev.machine_id, "public_key": self.dev.public,
                                                          "hostname": f.get("hostname"), "domain": f.get("domain"),
                                                          "user": f.get("user"), "os": f.get("os"),
                                                          "components": {"wireguard": wgv} if wgv else {}})
        self.uma_wg = next((x for x in r.get("components") or [] if x.get("name") == "wireguard"), None)
        set_status(update_state=r.get("status"), wg_source="UMA" if self.uma_wg else "Hersteller")
        return r

    def uma_fetch(self, item: dict, program: str) -> bytes:
        """Download from UMA and check SHA-256 + UMA signature for this program/component."""
        blob = request(self.dev, self.uma_base(), "GET", item["url"], raw=True, timeout=900)
        sha = hashlib.sha256(blob).hexdigest()
        msg = f"uma-release\n{program}\n{item['version']}\n{sha}".encode()
        if sha != item["sha256"] or not ed25519.verify(base64.b64decode(self.conf["update_key"]), msg, base64.b64decode(item["signature"])):
            raise RuntimeError(f"{program} {item['version']} von UMA hat eine ungültige Signatur – wird nicht installiert")
        return blob

    def restart_running(self) -> None:
        """After a WireGuard update: start the tunnels that should run."""
        for n in self.names():
            if self.is_on(n) and self.wg.svc_state(n) not in ("RUNNING", "MISSING"):
                self.wg.start(n)

    def wireguard_from_uma(self) -> bool:
        """Install/update WireGuard from UMA if UMA offers it. True = UMA is responsible for WireGuard."""
        wg = self.uma_wg
        if not wg:
            return False
        have = self.wg.version() if self.wg.installed() else ""
        if have and vkey(wg["version"]) <= vkey(have):
            return True
        set_status(state="installing" if not have else STATUS.get("state"), message=f"WireGuard {wg['version']} wird aus UMA installiert …")
        blob = self.uma_fetch(wg, "wireguard")
        d = os.path.join(DATA, "downloads")
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, wg.get("filename") or f"wireguard-{wg['version']}.msi")
        with open(f, "wb") as fh:
            fh.write(blob)
        try:
            self.wg.install_file(wg["version"], f)
        finally:
            try:
                os.remove(f)
            except OSError:
                pass
        self.event(f"WireGuard {wg['version']} aus UMA installiert" + (f" (vorher {have})" if have else ""))
        if have:
            self.restart_running()
        set_status(message="")
        return True

    # ----- WireGuard install / update
    def ensure_wireguard(self) -> None:
        if self.wg.installed():
            self.wg.disable_manager()
            return
        set_status(state="installing", message="WireGuard wird installiert …")
        try:
            if self.uma_base() and self.uma_check() is not None and self.wireguard_from_uma():
                return
        except Exception as e:  # noqa: BLE001 – UMA not reachable → vendor
            log("WireGuard aus UMA nicht möglich, nehme den Hersteller:", e)
        v, url = WireGuard.latest()
        self.wg.install(v, url)
        self.event(f"WireGuard {v} vom Hersteller installiert")

    def wireguard_update(self) -> None:
        """Daily: newer WireGuard directly from the vendor – only if UMA does not provide WireGuard."""
        self.next_wg = time.time() + WG_CHECK_EVERY
        if not self.wg.installed() or self.uma_wg:
            return
        try:
            v, url = WireGuard.latest()
            have = self.wg.version()
            if vkey(v) > vkey(have):
                set_status(message=f"WireGuard {v} wird installiert …")
                self.wg.install(v, url)
                self.event(f"WireGuard aktualisiert: {have} → {v} (Hersteller)")
                self.restart_running()
                set_status(message="")
        except Exception as e:  # noqa: BLE001
            log("WireGuard-Update:", e)
            self.next_wg = time.time() + 3600

    # ----- self update + components through UMA
    def self_update(self) -> None:
        self.next_self = time.time() + SELF_CHECK_EVERY
        try:
            r = self.uma_check()
            if r is None:
                return
            if self.wg.installed():
                self.wireguard_from_uma()
            u = r.get("update")
            if not u:
                return
            blob = self.uma_fetch(u, PROGRAM)
            d = os.path.join(DATA, "update")
            os.makedirs(d, exist_ok=True)
            new = os.path.join(d, f"vera-connect-{u['version']}.exe")
            with open(new, "wb") as fh:
                fh.write(blob)
            self.event(f"VERA-Connect {u['version']} geladen und geprüft – wird installiert")
            if SIMULATE or not COMPILED:
                log("[simuliert/nicht kompiliert] Selbst-Update übersprungen:", new)
                return
            target = os.path.join(home_dir(), "vera-connect.exe")
            pid = spawn_detached([new, "upgrade", "--target", target])
            log(f"Update-Prozess gestartet (PID {pid})")
        except HttpError as e:
            log("Update-Server:", e)
            set_status(update_state=f"Fehler: {e.detail}")
            self.next_self = time.time() + 3600
        except Exception as e:  # noqa: BLE001
            import traceback
            log("Selbst-Update:", e, traceback.format_exc()[-700:])
            set_status(update_state=f"Fehler: {e}")
            self.next_self = time.time() + 3600

    # ----- flags of the tray / window (any user)
    def flags(self) -> None:
        d = os.path.join(DATA, "ui")
        try:
            files = os.listdir(d)
        except OSError:
            return
        for f in files:
            if not f.endswith(".flag") or f in ("live.flag", "refresh.flag"):
                continue
            if not take_flag(f):
                continue
            try:
                if f == "disconnect.flag":                         # tray "Trennen": everything the user may switch off
                    for n in self.names():
                        if self.is_on(n):
                            try:
                                self.set_on(n, False)
                            except CmdError as e:
                                self.event(str(e))
                elif f == "connect.flag":
                    if self.default_name():
                        self.set_on(self.default_name(), True)
                elif f.startswith(("connect@", "disconnect@")):
                    on = f.startswith("connect@")
                    self.set_on(f.split("@", 1)[1][:-5], on)
            except CmdError as e:
                self.event(str(e))
                set_status(message=str(e))

    def pending_flags(self) -> bool:
        try:
            return any(f.endswith(".flag") and f != "live.flag" for f in os.listdir(os.path.join(DATA, "ui")))
        except OSError:
            return False

    # ----- watchdog (every tunnel that should run)
    def watch(self) -> None:
        self.flags()
        names = self.names()
        if not names:
            set_status(tunnel_state="waiting", tunnels=[])
            return
        self.refresh_local()
        dump = self.wg.dump() if any(self.is_on(n) for n in names) else {}
        for n in names:
            try:
                self.watch_one(n, dump)
            except Exception as e:  # noqa: BLE001
                self.rt.setdefault(n, {})["state"] = "missing"
                set_status(last_error=str(e)[:300])
                log(f"Tunnel {n}:", e)
        rows = self.rows(dump)
        on = [r for r in rows if r["on"]]
        vt = next((r for r in rows if r["source"] == "vera"), None)
        if not on:
            state = "user_off"
        elif any(r["state"] in ("down", "missing") for r in on):
            state = "down"
        elif any(r["state"] == "connecting" for r in on):
            state = "ready"
        elif all(r["state"] == "home" for r in on):
            state = "home"
        else:
            state = "up"
        prim = next((r for r in on if r["default"]), on[0] if on else None)
        extra = {"state": state, **({"message": ""} if state in ("up", "home") else {})}
        tstate = ("user_off" if not vt["on"] else vt["state"]) if vt else "waiting"
        set_status(tunnel_state={"idle": "up", "connecting": "down", "off": "user_off"}.get(tstate, tstate), tunnels=rows,
                   wg_version=self.wg.version() if self.wg.installed() else "",
                   tunnel=prim["name"] if prim else self.default_name(), default=self.default_name(),
                   last_handshake=(prim or {}).get("last_handshake", 0), **extra)

    def watch_one(self, n: str, dump: dict) -> None:
        r = self.rt.setdefault(n, {"started": time.time(), "pause": 60, "next": 0, "state": "off"})
        s = self.wg.svc_state(n)
        if not self.is_on(n):
            if s != "MISSING":
                self.wg.remove_tunnel(n)
            r["state"] = "off"
            return
        home, why = self.at_home(n)
        if home:                                                    # in the home network: no tunnel needed
            if s != "MISSING":
                self.wg.remove_tunnel(n)
            if r.get("state") != "home":
                self.event(f"Tunnel {n} pausiert – im Heimnetz ({why})")
            r.update(state="home", home_why=why)
            return
        if r.get("state") == "home":
            self.event(f"Tunnel {n}: Heimnetz verlassen – wird wieder verbunden")
            r.update(state="connecting", started=time.time(), home_why="")
            s = self.wg.svc_state(n)
        if s == "MISSING":
            text = self.config_of(n)
            if not text:
                if n == self.vera_name():
                    self.state["config_hash"] = ""                  # fetch again at the next poll
                    self.next_poll = 0
                r["state"] = "missing"
                return
            self.ensure_wireguard()
            self.wg.install_tunnel(n, text)
            r.update(started=time.time(), state="connecting")
            if r.get("seen"):
                self.event(f"Tunnel {n} fehlte – aus gespeicherter Konfiguration wiederhergestellt")
            r["seen"] = True
            return
        r["seen"] = True
        if s != "RUNNING":
            if time.time() >= r.get("next", 0):
                self.wg.start(n)
                r["started"] = time.time()
                self.event(f"Tunnel {n} war aus – neu gestartet")
                r["next"] = time.time() + 30
            r["state"] = "down"
            return
        hs = (dump.get(n) or {}).get("last_handshake") or 0
        age = time.time() - hs if hs else None
        if age is not None and age <= HANDSHAKE_MAX:
            r.update(state="up", pause=60)
            return
        watched = n == self.vera_name() or self.summary(n).get("keepalive")
        if not watched:                                             # no keepalive: a handshake only comes with traffic
            r["state"] = "idle"
            return
        r["state"] = "down" if time.time() - r["started"] >= HANDSHAKE_MAX else "connecting"
        if time.time() - r["started"] < HANDSHAKE_MAX or time.time() < r.get("next", 0):
            return
        if not internet_ok():
            set_status(message="kein Internet – warte")
            return
        log(f"Tunnel {n}: kein Handshake seit {int(age) if age else 'Start'} s – wird neu verbunden (nächster Versuch frühestens in {r['pause'] // 60} min)")
        self.wg.stop(n)
        time.sleep(2)
        self.wg.start(n)
        r["started"] = time.time()
        r["next"] = time.time() + r["pause"]
        r["pause"] = min(r["pause"] * 2, 1800)
        self.events.append(f"Tunnel {n} ohne Verbindung – neu verbunden")

    # ----- live data for the window (only while it is open: it touches ui\live.flag)
    def live(self) -> None:
        try:
            if time.time() - os.path.getmtime(os.path.join(DATA, "ui", "live.flag")) > 15:
                return
        except OSError:
            return
        dump = self.wg.dump()
        data = {"t": time.time(), "tunnels": {n: {k: v for k, v in (dump.get(n) or {}).items() if k != "peers"} | {"running": n in dump}
                                              for n in self.names()}}
        try:
            tmp = _path("live.json.new")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, _path("live.json"))
        except OSError:
            pass

    # ----- commands of the window / CLI (cmd\ is writable for administrators only)
    def commands(self) -> bool:
        d = os.path.join(DATA, CMD_DIR)
        try:
            files = sorted((f for f in os.listdir(d) if f.endswith(".req.json")), key=lambda f: os.path.getmtime(os.path.join(d, f)))
        except OSError:
            return False
        for f in files:
            p = os.path.join(d, f)
            try:
                with open(p, encoding="utf-8") as fh:
                    req = json.load(fh)
            except (OSError, ValueError):
                req = None
            try:
                os.remove(p)                                        # may contain keys – away at once
            except OSError:
                pass
            if not isinstance(req, dict):
                continue
            rid = re.sub(r"[^A-Za-z0-9]", "", str(req.get("id") or f[:-9]))[:32] or secrets.token_hex(6)
            try:
                res = {"ok": True, "data": self.command(req) or {}}
            except (CmdError, wgconf.ConfError) as e:
                res = {"ok": False, "message": str(e)}
            except HttpError as e:
                res = {"ok": False, "message": e.detail if e.status != 404 or "unbekannt" in e.detail
                       else "VERA kennt keine Sicherungen – VERA 1.3 oder neuer nötig"}
            except (OSError, ValueError) as e:
                res = {"ok": False, "message": f"VERA nicht erreichbar: {explain(e)}"}
            except Exception as e:  # noqa: BLE001
                import traceback
                log("Befehl", req.get("action"), "fehlgeschlagen:", traceback.format_exc()[-600:])
                res = {"ok": False, "message": f"Fehler: {e}"}
            log(f"Befehl {req.get('action')}: {'ok' if res['ok'] else res['message']}")
            try:
                tmp = os.path.join(d, rid + ".res.new")
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(res, fh, ensure_ascii=False)
                os.replace(tmp, os.path.join(d, rid + ".res.json"))
            except OSError as e:
                log("Antwort nicht schreibbar:", e)
        for f in os.listdir(d) if files else []:                     # old answers nobody picked up
            p = os.path.join(d, f)
            try:
                if f.endswith(".res.json") and time.time() - os.path.getmtime(p) > 600:
                    os.remove(p)
            except OSError:
                pass
        return bool(files)

    def _check_new_name(self, name: str, allow: str | None = None) -> str:
        name = (name or "").strip()
        if not wgconf.valid_name(name):
            raise CmdError("Name: 1–32 Zeichen, nur Buchstaben, Ziffern und - _ . = + (keine Leerzeichen)")
        other = self.find(name)
        if other and other != allow:
            raise CmdError(f"Ein Tunnel „{other}“ gibt es schon")
        return name

    def command(self, req: dict) -> dict | None:
        a = req.get("action")
        if a in ("create", "edit"):
            text = str(req.get("text") or "")
            wgconf.parse(text)
            if a == "create":
                name = self._check_new_name(req.get("name"))
                self.local[name] = {"config": protect(text.encode()), "on": False, "created": time.time(),
                                    "origin": str(req.get("origin") or "von Hand")[:40]}
                self.keep()
                self.event(f"Tunnel {name} angelegt ({self.local[name]['origin']})")
                if req.get("connect"):
                    self.set_on(name, True, "Fenster")
                return {"name": name}
            name = self.find(req.get("name"))
            if name not in self.local:
                raise CmdError("Nur eigene Tunnel lassen sich bearbeiten – der Tunnel von VERA kommt aus VERA")
            self.local[name]["config"] = protect(text.encode())
            self.keep()
            if self.is_on(name):
                self.wg.remove_tunnel(name)                         # the watchdog installs the new version
            self.rt.pop(name, None)
            self.event(f"Tunnel {name} geändert")
            return {"name": name}
        if a == "get":
            name = self.find(req.get("name"))
            if name not in self.local:
                raise CmdError("Die Konfiguration des VERA-Tunnels verwaltet VERA")
            return {"name": name, "text": self.config_of(name)}
        if a == "rename":
            old = self.find(req.get("name"))
            if not old:
                raise CmdError("Tunnel unbekannt")
            new = self._check_new_name(req.get("new"), allow=old)
            if new == old:
                return {"name": new}
            was_on = self.is_on(old)
            if self.wg.svc_state(old) != "MISSING":
                self.wg.remove_tunnel(old)
            if old in self.state["home"]:
                self.state["home"][new] = self.state["home"].pop(old)
            self.home_cache.pop(old, None)
            if old == self.vera_name():
                c = self.conf
                c["tunnel"] = new
                save("config.json", c)
                self.state["tunnel"] = new
            else:
                self.local[new] = self.local.pop(old)
            if self.state.get("default") == old:
                self.state["default"] = new
            self.rt.pop(old, None)
            self.keep()
            self.event(f"Tunnel {old} heißt jetzt {new}" + (" – wird neu verbunden" if was_on else ""))
            return {"name": new}
        if a == "delete":
            name = self.find(req.get("name"))
            if name not in self.local:
                raise CmdError("Der Tunnel von VERA lässt sich hier nicht löschen (in VERA sperren oder entfernen)")
            self.wg.remove_tunnel(name)
            del self.local[name]
            self.state["home"].pop(name, None)
            if self.state.get("default") == name:
                self.state["default"] = None
            self.rt.pop(name, None)
            self.keep()
            self.event(f"Tunnel {name} gelöscht")
            return {}
        if a == "home":
            name = self.find(req.get("name"))
            if not name:
                raise CmdError("Tunnel unbekannt")
            import ipaddress
            nets = req.get("networks") or []
            if isinstance(nets, str):
                nets = [x for x in re.split(r"[,;\s]+", nets) if x]
            for x in nets:
                try:
                    if ipaddress.ip_network(x, strict=False).version != 4:
                        raise ValueError
                except ValueError as e:
                    raise CmdError(f"„{x}“ ist kein IPv4-Netz (z. B. 192.168.99.0/24)") from e
            check = str(req.get("check") or "").strip()[:200]
            self.state["home"][name] = {"enabled": bool(req.get("enabled", True)), "networks": nets, "check": check}
            self.home_cache.pop(name, None)
            self.keep()
            self.event(f"Heimnetz-Erkennung für {name}: {'an' if req.get('enabled', True) else 'aus'}"
                       + (f", Netze {', '.join(nets)}" if nets else "") + (f", Prüfung {check}" if check else ""))
            return {"name": name}
        if a == "default":
            name = self.find(req.get("name"))
            if not name:
                raise CmdError("Tunnel unbekannt")
            self.state["default"] = name
            self.keep()
            self.event(f"Standard-Tunnel: {name}")
            return {"name": name}
        if a in ("connect", "disconnect"):
            self.set_on(req.get("name"), a == "connect", "Fenster")
            return {}
        if a == "backup_create":
            return self.backup_create(str(req.get("passphrase") or ""), str(req.get("comment") or "")[:200])
        if a == "backup_list":
            return self.vera_call("/client/backup/list", {})
        if a == "backup_delete":
            return self.vera_call("/client/backup/delete", {"id": int(req.get("backup_id") or 0)})
        if a == "backup_restore":
            return self.backup_restore(int(req.get("backup_id") or 0), str(req.get("passphrase") or ""), bool(req.get("settings")))
        raise CmdError(f"Unbekannter Befehl {a}")

    # ----- backup in VERA (tunnels + settings; sealed with a passphrase VERA never sees)
    def vera_call(self, path: str, data: dict) -> dict:
        url = self.conf.get("url")
        if not url:
            raise CmdError("Adresse von VERA fehlt")
        return request(self.dev, url, "POST", path, data, timeout=60)

    def backup_create(self, passphrase: str, comment: str) -> dict:
        c = self.conf
        tunnels = [{"name": n, "config": self.config_of(n), "on": self.is_on(n), "origin": t.get("origin", ""),
                    "created": t.get("created"), "home": self.home_cfg(n)} for n, t in sorted(self.local.items())]
        payload = {"format": "vera-connect-backup", "version": 1, "client_version": VERSION, "created": time.time(),
                   "hostname": self.dev.facts.get("hostname", ""), "default": self.default_name(), "vera_tunnel": self.vera_name(),
                   "settings": {k: c.get(k, "") for k in ("url", "update_url", "update_key", "tunnel")}, "tunnels": tunnels,
                   "vera_home": self.home_cfg(self.vera_name()) if self.vera_name() else None}
        blob = wgconf.seal(payload, passphrase)
        meta = {"tunnels": [t["name"] for t in tunnels], "vera_tunnel": self.vera_name() or "", "default": self.default_name() or "",
                "client_version": VERSION, "hostname": payload["hostname"], "comment": comment}
        r = self.vera_call("/client/backup/upload", {"meta": meta, "blob": blob})
        self.event(f"Sicherung in VERA angelegt ({len(tunnels)} eigene Tunnel)")
        return r

    def backup_restore(self, bid: int, passphrase: str, settings: bool) -> dict:
        r = self.vera_call("/client/backup/get", {"id": bid})
        data = wgconf.unseal(r["blob"], passphrase)
        if data.get("format") != "vera-connect-backup":
            raise CmdError("Das ist keine Sicherung von VERA-Connect")
        new = {}
        for t in data.get("tunnels") or []:
            text = t.get("config") or ""
            wgconf.parse(text)
            name = wgconf.safe_name(t.get("name") or "Tunnel")
            if self.vera_name() and name.lower() == self.vera_name().lower():
                name = name[:28] + "-alt"
            new[name] = {"config": protect(text.encode()), "on": bool(t.get("on")), "created": t.get("created") or time.time(),
                         "origin": (t.get("origin") or "Sicherung")[:40]}
            if isinstance(t.get("home"), dict):
                self.state["home"][name] = t["home"]
        for n in list(self.local):                                  # replace the own tunnels completely
            if n not in new or self.config_of(n) != unprotect(new[n]["config"]).decode():
                self.wg.remove_tunnel(n)
                self.rt.pop(n, None)
        self.state["local"] = new
        if isinstance(data.get("vera_home"), dict) and self.vera_name():
            self.state["home"][self.vera_name()] = data["vera_home"]
        self.home_cache.clear()
        d = data.get("default")
        if d == data.get("vera_tunnel") and self.vera_name():
            d = self.vera_name()
        self.state["default"] = d if d in self.names() else None
        applied = ["Tunnel"]
        if settings:
            c, s = self.conf, data.get("settings") or {}
            changed_url = s.get("url") and s["url"] != c.get("url")
            for k in ("url", "update_url", "update_key", "tunnel"):
                if s.get(k) is not None:
                    c[k] = s[k]
            save("config.json", c)
            if changed_url:
                self.state.pop("enrolled", None)
                self.next_poll = 0
            applied.append("Einstellungen")
        self.keep()
        self.event(f"Sicherung vom {time.strftime('%d.%m.%Y %H:%M', time.localtime(data.get('created') or 0))} "
                   f"wiederhergestellt: {len(new)} eigene Tunnel" + (" + Einstellungen" if settings else ""))
        return {"tunnels": sorted(new), "applied": applied}

    def loop(self) -> None:
        log(f"{APP} {VERSION} startet (Daten: {DATA}{', SIMULATION' if SIMULATE else ''})")
        if COMPILED:                                                # leftovers of a self-update (renamed running EXE)
            import glob
            for f in glob.glob(os.path.join(home_dir(), "vera-connect.exe.old-*")):
                try:
                    os.remove(f)
                except OSError:
                    pass
        set_status(state="start", message="", tunnel=self.default_name(), vera=self.conf.get("url", ""),
                   uma=self.conf.get("update_url", ""))
        while not STOP.is_set():
            try:
                if take_flag("refresh.flag"):
                    self.state["config_hash"] = ""
                    self.next_poll = 0
                    log("Konfiguration neu holen (Tray)")
                if time.time() >= self.next_poll:
                    self.poll()
                self.watch()
                if time.time() >= self.next_wg and self.names():
                    self.wireguard_update()
                if time.time() >= self.next_self:
                    self.self_update()
            except Exception as e:  # noqa: BLE001 – the service must never die
                import traceback
                log("Fehler:", e, traceback.format_exc()[-800:])
                set_status(last_error=str(e)[:300])
            end = time.time() + WATCH_EVERY
            while not STOP.is_set() and time.time() < end:
                try:
                    if self.pending_flags() or self.commands():
                        break
                    if time.time() >= self.next_net:
                        self.next_net = time.time() + 5
                        if self.refresh_local() and self.names():
                            self.home_cache.clear()
                            break
                    self.live()
                except Exception as e:  # noqa: BLE001
                    log("Fehler:", e)
                STOP.wait(1)
        log(f"{APP} beendet")


def diagnose(data: str | None = None) -> str:
    """Connection check step by step (name → port → certificate → answer of VERA/UMA) plus status and the end of the
    log. Runs as normal user (tray) or admin – it only reads status.json/connect.log and the addresses in it."""
    from urllib.parse import urlsplit
    d = data or DATA
    out = [f"VERA-Connect {VERSION} – Diagnose {time.strftime('%d.%m.%Y %H:%M:%S')}",
           f"Rechner: {os.environ.get('COMPUTERNAME', socket.gethostname())} · Benutzer: {os.environ.get('USERNAME', '')}", ""]
    try:
        st = json.load(open(os.path.join(d, "status.json"), encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    conf = load("config.json") if os.access(os.path.join(d, "config.json"), os.R_OK) else {}
    targets = [("VERA", conf.get("url") or st.get("vera") or ""), ("UMA", conf.get("update_url") or st.get("uma") or "")]
    out.append(f"Dienst: Zustand „{st.get('state', '?')}“ · {st.get('message') or ''}")
    if st.get("last_error"):
        out.append(f"Letzter Fehler des Dienstes: {st['last_error']}")
    out.append("")
    for name, base in targets:
        if not base:
            out.append(f"{name}: keine Adresse eingetragen")
            continue
        u = urlsplit(base)
        host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
        out.append(f"── {name}: {base}")
        try:
            ips = sorted({a[4][0] for a in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
            out.append(f"  1. Name aufgelöst: {', '.join(ips)}")
        except OSError as e:
            out.append(f"  1. Name NICHT auflösbar: {e}  → DNS prüfen")
            continue
        reach = []
        for ip in ips:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            t0 = time.time()
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as sk:
                    sk.settimeout(6)
                    sk.connect((ip, port))
                reach.append(ip)
                out.append(f"  2. {'IPv6' if fam == socket.AF_INET6 else 'IPv4'} {ip} Port {port}: erreichbar ({int((time.time() - t0) * 1000)} ms)")
            except OSError as e:
                out.append(f"  2. {'IPv6' if fam == socket.AF_INET6 else 'IPv4'} {ip} Port {port}: NICHT erreichbar ({e.__class__.__name__}: {e})")
        if not reach:
            out.append("     → keine Adresse erreichbar: Weiterleitung/Firewall/Proxy prüfen")
            continue
        if len(reach) < len(ips):
            out.append("     → nicht alle Adressen erreichbar. Ist nur IPv6 betroffen: am Proxy/Firewall Port %d für IPv6 freigeben "
                       "oder den AAAA-Eintrag im DNS entfernen. VERA-Connect nimmt IPv4 zuerst." % port)
        if u.scheme == "https":
            raw = ssl.create_default_context()
            raw.check_hostname, raw.verify_mode = False, ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=10) as sk, raw.wrap_socket(sk, server_hostname=host) as tl:
                    der = tl.getpeercert(binary_form=True) or b""
                subj, iss = _cert_names(ssl.DER_cert_to_PEM_cert(der))
                cn = lambda x: ", ".join(v for rdn in (x or ()) for k, v in rdn if k in ("commonName", "organizationName"))  # noqa: E731
                out.append(f"  3. Zertifikat: {cn(subj)} · ausgestellt von {cn(iss)}")
                plain = ssl.create_default_context()
                try:
                    with socket.create_connection((host, port), timeout=10) as sk, plain.wrap_socket(sk, server_hostname=host):
                        pass
                    out.append("     Prüfung (OpenSSL): in Ordnung")
                except ssl.SSLError as e:
                    out.append(f"     Prüfung (OpenSSL): {getattr(e, 'verify_message', e)}")
                    if getattr(e, "verify_code", 0) in (2, 20, 21):
                        out.append("     → der Server schickt die Zertifikatskette unvollständig (am Proxy „fullchain“ eintragen)")
                chain = windows_chain(der, host)
                out.append(f"     Prüfung (Windows): {'vertrauenswürdig, Kette mit ' + str(len(chain)) + ' Zertifikat(en)' if chain else 'NICHT vertrauenswürdig'}")
            except (OSError, ssl.SSLError, ValueError) as e:
                out.append(f"  3. TLS-Fehler: {e}")
        path = "/.well-known/sysrix-app" if name == "VERA" else "/u/info"
        try:
            ctx = _ssl
            try:
                r = urllib.request.urlopen(base.rstrip("/") + path, timeout=15, context=ctx)
            except urllib.error.URLError as e:
                if isinstance(e, urllib.error.HTTPError) or not _is_chain_error(e) or not fetch_missing_intermediate(base):
                    raise
                r = urllib.request.urlopen(base.rstrip("/") + path, timeout=15, context=_ssl)
            body = r.read(400)
            try:
                info = json.loads(body)
                out.append(f"  4. Antwort: {info.get('name', '?')} {info.get('version', '')} – in Ordnung")
            except ValueError:
                out.append(f"  4. Antwort ist kein JSON (Anmeldeseite/Proxy davor?): {body[:120]!r}")
        except urllib.error.HTTPError as e:
            out.append(f"  4. Antwort HTTP {e.code} {e.reason}")
        except (OSError, ValueError) as e:
            out.append(f"  4. Keine Antwort: {explain(e)}")
        out.append("")
    try:
        lines = open(os.path.join(d, "connect.log"), encoding="utf-8", errors="replace").read().splitlines()[-40:]
        out += ["── Protokoll (letzte 40 Zeilen)", *lines]
    except OSError as e:
        out.append(f"Protokoll nicht lesbar: {e}")
    return "\n".join(out)


def internet_ok() -> bool:
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((host, 53), timeout=3):
                return True
        except OSError:
            continue
    return False


# ------------------------------------------------------------------ install / uninstall
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VERA-Connect"


def exe_path() -> str:
    return os.path.join(home_dir(), "vera-connect.exe")


def _reg(path: str, values: dict | None) -> None:
    import winreg
    if values is None:
        try:
            winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, path, winreg.KEY_WOW64_64KEY, 0)
        except OSError:
            pass
        return
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    for n, v in values.items():
        winreg.SetValueEx(k, n, 0, winreg.REG_DWORD if isinstance(v, int) else winreg.REG_SZ, v)
    winreg.CloseKey(k)


def tray_autostart(on: bool) -> None:
    import winreg
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        if on:
            winreg.SetValueEx(k, APP, 0, winreg.REG_SZ, f'"{exe_path()}" tray')
        else:
            try:
                winreg.DeleteValue(k, APP)
            except FileNotFoundError:
                pass
        winreg.CloseKey(k)
    except OSError as e:
        log("Tray-Autostart:", e)


CONFIG_MARK = b"\nVERA-CONNECT-CONFIG:"
CONFIG_KEYS = {"url": "URL", "update_url": "UPDATEURL", "update_key": "UPDATEKEY", "enroll_key": "ENROLLKEY", "tunnel": "TUNNEL"}


def embedded_config() -> dict:
    """Settings appended to the EXE (VERA › Rechner › Installer): a line "VERA-CONNECT-CONFIG:{json}" at the very end.
    Windows ignores data behind the program; setup parameters given on the command line still win."""
    if not COMPILED:
        return {}
    try:
        with open(os.path.abspath(sys.argv[0]), "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 65536))
            tail = f.read()
        i = tail.rfind(CONFIG_MARK)
        if i < 0:
            return {}
        d = json.loads(tail[i + len(CONFIG_MARK):].split(b"\n", 1)[0])
        return {CONFIG_KEYS[k]: str(v) for k, v in d.items() if k in CONFIG_KEYS and v is not None}
    except (OSError, ValueError):
        return {}


def parse_params(argv: list[str]) -> dict:
    """MSI-like KEY=VALUE parameters and /S (silent) – for GPO, DORA, Intune."""
    out = {}
    for a in argv:
        if a.upper() in ("/S", "/SILENT", "/QUIET", "/Q", "-S"):
            out["silent"] = True
        elif "=" in a:
            k, v = a.split("=", 1)
            k = k.strip().lstrip("/-").upper()
            if k in ("URL", "ENROLLKEY", "UPDATEURL", "UPDATEKEY", "TUNNEL"):
                out[k] = v.strip().strip('"')
    return out


def ask(title: str, prompt: str, default: str = "") -> str | None:
    """Small input box (PowerShell / VisualBasic InputBox) – None = cancelled."""
    esc = lambda s: s.replace("'", "''")  # noqa: E731
    c, o = powershell("Add-Type -AssemblyName Microsoft.VisualBasic\n"
                      f"$r = [Microsoft.VisualBasic.Interaction]::InputBox('{esc(prompt)}', '{esc(title)}', '{esc(default)}')\n"
                      "if ($r -eq '') { 'ABBRUCH' } else { 'WERT:' + $r }", 3600)
    line = (o.strip().splitlines() or [""])[-1]
    return line[5:].strip() if line.startswith("WERT:") else None


def box(text: str, icon: int = 0x40) -> None:
    if WIN:
        ctypes.windll.user32.MessageBoxW(None, text, APP, icon)
    else:
        print(text)


def normalize_url(u: str) -> str:
    u = (u or "").strip().rstrip("/")
    if u and not u.startswith(("http://", "https://")):
        u = "https://" + u
    for suffix in ("/client", "/getconfig"):
        if u.endswith(suffix):
            u = u[: -len(suffix)]
    return u


def install(p: dict) -> None:
    if not WIN:
        raise SystemExit("VERA-Connect läuft nur unter Windows.")
    import winservice
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Bitte als Administrator ausführen.")
    conf = load("config.json")
    silent = p.get("silent")
    if p.get("URL"):
        conf["url"] = normalize_url(p["URL"])
    elif not conf.get("url") and not silent:
        v = ask(APP, "Adresse von VERA (z. B. https://vera.<Domain>)\nLeer lassen = später in den Einstellungen eintragen.")
        if v is None:
            raise SystemExit("Abgebrochen.")
        conf["url"] = normalize_url(v)
    if "UPDATEURL" in p:                                             # also "" = no updates on purpose
        conf["update_url"] = normalize_url(p["UPDATEURL"])
    elif "update_url" not in conf and not silent:
        v = ask(APP, "Adresse des Update-Servers (UMA), z. B. https://update.<Domain>\nLeer = keine automatischen Updates von VERA-Connect.")
        conf["update_url"] = normalize_url(v or "")
    for k, n in (("ENROLLKEY", "enroll_key"), ("UPDATEKEY", "update_key"), ("TUNNEL", "tunnel")):
        if p.get(k):
            conf[n] = p[k]
    if conf.get("url", "").startswith("http://"):
        log("Achtung: VERA ohne HTTPS – nur für Tests")
    save("config.json", conf)
    if COMPILED:                                                   # keep a copy in Program Files
        me, target = os.path.abspath(sys.argv[0]), exe_path()
        if os.path.normcase(me) != os.path.normcase(target):
            if winservice._query_state() is not None:
                winservice.stop()
            os.makedirs(home_dir(), exist_ok=True)
            try:                                                   # the tray of this session holds the EXE open
                import tray
                if tray.close_running():
                    time.sleep(2)
            except Exception:  # noqa: BLE001
                pass
            if not replace_exe(me, target):
                raise SystemExit(f"{target} ist gesperrt und ließ sich nicht ersetzen – VERA-Connect-Fenster/Tray schließen und erneut starten.")
            sys.argv[0] = target
    winservice.install(DATA)
    harden()
    tray_autostart(True)
    _reg(UNINSTALL_KEY, {"DisplayName": APP, "DisplayVersion": VERSION, "Publisher": "SysriX",
                         "UninstallString": f'"{exe_path()}" uninstall', "QuietUninstallString": f'"{exe_path()}" uninstall /S',
                         "DisplayIcon": exe_path(), "InstallLocation": home_dir(), "NoModify": 1, "NoRepair": 1})
    log(f"{APP} {VERSION} installiert – VERA: {conf.get('url') or '(fehlt)'}, Updates: {conf.get('update_url') or '(aus)'}")


def start_tray() -> None:
    u = os.environ.get("USERNAME", "").upper()
    if u.endswith("$") or u == "SYSTEM" or not COMPILED:
        return
    try:
        subprocess.Popen([exe_path(), "tray"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, creationflags=0x00000008 | 0x00000200)
    except OSError as e:
        log("Tray-Start:", e)


def uninstall(silent: bool) -> None:
    import winservice
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Bitte als Administrator ausführen.")
    if not silent and ctypes.windll.user32.MessageBoxW(None, "VERA-Connect entfernen? Die WireGuard-Tunnel dieses Rechners werden dabei ebenfalls entfernt "
                                                       "(eigene Tunnel bleiben für eine Neuinstallation gespeichert). WireGuard selbst bleibt installiert.", APP, 0x34) != 6:
        return
    tray_autostart(False)
    try:
        import tray
        tray.close_running()
    except Exception:  # noqa: BLE001
        pass
    if winservice._query_state() is not None:
        winservice.remove()
    st = load("state.json")
    wg = WireGuard()
    for n in ([st["tunnel"]] if st.get("tunnel") else []) + list(st.get("local") or {}):
        wg.remove_tunnel(n)
    if st.get("local"):                                             # own tunnels stay (DPAPI) for a reinstall – switched off
        save("state.json", {"local": {n: {**t, "on": False} for n, t in st["local"].items()}, "default": st.get("default")})
    for f in (("state.json",) if not st.get("local") else ()) + ("status.json", "live.json"):
        try:
            os.remove(_path(f))
        except OSError:
            pass
    _reg(UNINSTALL_KEY, None)
    log(f"{APP} entfernt (Geräteschlüssel bleibt – bei Neuinstallation erkennt VERA den Rechner wieder)")
    if COMPILED and os.path.isdir(home_dir()):
        spawn_detached(f'cmd.exe /c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{home_dir()}"', breakaway=False)
    if not silent:
        box("VERA-Connect wurde entfernt.")


def replace_exe(src: str, target: str, tries: int = 15) -> bool:
    """Copy the new EXE over the installed one. A running EXE (tray/window of a logged-on user) cannot be overwritten,
    but renamed: it keeps running from the old file, every new start uses the new one (*.old-* removed later)."""
    for _ in range(tries):
        try:
            shutil.copy2(src, target)
            return True
        except OSError:
            try:
                old = f"{target}.old-{int(time.time())}"
                os.replace(target, old)
                shutil.copy2(src, target)
                log("Laufende EXE umbenannt nach", os.path.basename(old), "– neue Version liegt bereit")
                return True
            except OSError:
                time.sleep(1)
    return False


def upgrade(target: str) -> None:
    """Run from the downloaded new exe: stop the service, replace the installed exe, start the service."""
    import winservice
    log(f"Selbst-Update auf {VERSION}: ersetze {target}")
    winservice.stop()
    if not replace_exe(os.path.abspath(sys.argv[0]), target, 30):
        log("Selbst-Update: Datei blieb gesperrt – alte Version läuft weiter")
    _reg(UNINSTALL_KEY, {"DisplayVersion": VERSION})
    winservice.start()
    log("Selbst-Update fertig")


def configure() -> None:
    """Settings (admin, from the tray): addresses of VERA and UMA."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        elevate(["configure"])
        return
    conf = load("config.json")
    v = ask(APP, "Adresse von VERA", conf.get("url", ""))
    if v is None:
        return
    u = ask(APP, "Adresse des Update-Servers (UMA) – leer = keine Updates", conf.get("update_url", ""))
    if u is None:
        return
    conf["url"], new_update = normalize_url(v), normalize_url(u)
    if new_update != conf.get("update_url"):
        conf.pop("update_key", None)                     # different UMA → pin its key again
    conf["update_url"] = new_update
    save("config.json", conf)
    st = load("state.json")
    st.pop("enrolled", None)
    save("state.json", st)
    os.makedirs(os.path.join(DATA, "ui"), exist_ok=True)
    open(os.path.join(DATA, "ui", "refresh.flag"), "w").close()
    box("Gespeichert – VERA-Connect meldet sich gleich bei der neuen Adresse.")


def elevate(args: list[str]) -> bool:
    exe = os.path.abspath(sys.argv[0]) if COMPILED else sys.executable
    params = subprocess.list2cmdline(args if COMPILED else [os.path.abspath(__file__), *args])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32


def setup(argv: list[str]) -> None:
    """Double-click / setup parameters: elevate, install, start the tray."""
    emb = embedded_config()
    p = {**emb, **parse_params(argv)}
    if emb:
        log("Eingebaute Einstellungen gefunden:", ", ".join(f"{k}={'…' if 'KEY' in k else v}" for k, v in emb.items()))
    if not ctypes.windll.shell32.IsUserAnAdmin():
        if not elevate(argv):
            box("Für die Installation werden Administratorrechte gebraucht.", 0x10)
        return
    try:
        install(p)
    except SystemExit as e:
        if not p.get("silent") and str(e) != "Abgebrochen.":
            box(f"Installation fehlgeschlagen:\n{e}", 0x10)
        return
    except Exception as e:  # noqa: BLE001
        log("Installation:", e)
        if not p.get("silent"):
            box(f"Installation fehlgeschlagen:\n{e}", 0x10)
        sys.exit(1)
    if not p.get("silent"):                     # silent (GPO/DORA/Intune): the tray starts at the next logon
        start_tray()
        url = load("config.json").get("url")
        box("VERA-Connect ist installiert und läuft als Dienst.\n\n"
            + (f"Der Rechner meldet sich bei {url} an und erscheint dort unter „Rechner“ zur Freigabe. "
               "Danach richtet sich die VPN-Verbindung von selbst ein." if url else
               "Die Adresse von VERA fehlt noch – Rechtsklick auf das Symbol in der Taskleiste › Einstellungen."))


def send_command(req: dict, timeout: int = 180) -> dict:
    """Hand a command to the service (folder cmd, administrators only) and wait for its answer."""
    d = os.path.join(DATA, CMD_DIR)
    os.makedirs(d, exist_ok=True)
    rid = req.setdefault("id", secrets.token_hex(8))
    tmp = os.path.join(d, rid + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(req, f, ensure_ascii=False)
    os.replace(tmp, os.path.join(d, rid + ".req.json"))
    res = os.path.join(d, rid + ".res.json")
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(res):
            time.sleep(0.05)
            try:
                with open(res, encoding="utf-8") as f:
                    r = json.load(f)
                os.remove(res)
                return r
            except (OSError, ValueError):
                pass
        time.sleep(0.25)
    try:
        os.remove(os.path.join(d, rid + ".req.json"))
    except OSError:
        pass
    return {"ok": False, "message": "Der Dienst VeraConnect antwortet nicht – läuft er?"}


def admin_cmd(path: str) -> None:
    """Started elevated by the window of a normal user: pass the request on, write the answer next to it."""
    try:
        with open(path, encoding="utf-8") as f:
            req = json.load(f)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        r = send_command(req)
    except OSError as e:
        r = {"ok": False, "message": f"Befehl nicht übergeben: {e}"}
    tmp = path + ".res.new"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False)
    os.replace(tmp, path + ".res")


def _cli_result(r: dict) -> None:
    if not r.get("ok"):
        raise SystemExit("Fehler: " + str(r.get("message")))
    print(json.dumps(r.get("data") or {}, indent=2, ensure_ascii=False))


def cli_tunnel(a) -> None:
    if a.action == "list":
        st = load("status.json")
        for t in st.get("tunnels") or []:
            print(f"{'*' if t['default'] else ' '} {t['name']:<32} {'VERA ' if t['source'] == 'vera' else 'eigen'} "
                  f"{'an ' if t['on'] else 'aus'} {t['state']:<10} {t.get('endpoint', '')}"
                  + (f"  Heimnetz: {', '.join(t.get('home_networks') or []) or '–'}" if (t.get("home") or {}).get("enabled", True) else "  Heimnetz: aus")
                  + (f" ({t['home_why']})" if t.get("home_why") else ""))
        return
    req = {"action": a.action, "name": a.name}
    if a.action in ("import", "import-qr"):
        if a.action == "import":
            text = open(a.name, encoding="utf-8-sig").read()
            origin = "Datei " + os.path.basename(a.name)
        else:
            import qrdecode
            text = qrdecode.decode_file(a.name)
            origin = "QR-Code " + os.path.basename(a.name)
        wgconf.parse(text)
        req = {"action": "create", "name": a.new or wgconf.safe_name(os.path.splitext(os.path.basename(a.name))[0]), "text": text,
               "origin": origin, "connect": a.connect}
    elif a.action == "rename":
        req["new"] = a.new
    elif a.action == "home":                                       # tunnel home <Name> on|off [--networks …] [--check …]
        req.update(enabled=(a.new or "on").lower() not in ("off", "aus", "0"), networks=a.networks, check=a.check)
    _cli_result(send_command(req))


def cli_backup(a) -> None:
    req: dict = {"action": "backup_" + a.action}
    if a.action in ("create", "restore"):
        pw = os.environ.get("VC_BACKUP_PASSPHRASE")
        if not pw:
            import getpass
            pw = getpass.getpass("Kennwort der Sicherung: ")
        req["passphrase"] = pw
    if a.action == "create":
        req["comment"] = a.comment
    if a.action in ("restore", "delete"):
        req["backup_id"] = a.id
    if a.action == "restore":
        req["settings"] = a.settings
    _cli_result(send_command(req))


def main() -> None:
    global DATA, SIMULATE
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("/") or "=" in argv[0]:
        if WIN:
            setup(argv)
            return
    ap = argparse.ArgumentParser(description=APP)
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("install", help="installieren und als Dienst starten")
    for n in ("url", "enroll-key", "update-url", "update-key", "tunnel"):
        i.add_argument("--" + n, default="")
    i.add_argument("--silent", action="store_true")
    r = sub.add_parser("run", help="im Vordergrund laufen")
    r.add_argument("--data", default="")
    r.add_argument("--simulate", action="store_true", help="WireGuard nicht anfassen (Test)")
    r.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    u = sub.add_parser("uninstall")
    u.add_argument("--silent", action="store_true")
    sub.add_parser("status")
    dg = sub.add_parser("diagnose", help="Verbindung zu VERA/UMA prüfen und Bericht ausgeben")
    dg.add_argument("--out", default="", help="Bericht zusätzlich in diese Datei schreiben")
    sub.add_parser("version")
    sub.add_parser("embedded", help="eingebaute Einstellungen dieser EXE anzeigen")
    sub.add_parser("configure")
    g = sub.add_parser("upgrade", help=argparse.SUPPRESS)
    g.add_argument("--target", required=True)
    t = sub.add_parser("tray")
    t.add_argument("--data", default="")
    t.add_argument("--selbsttest", type=float, default=0, help=argparse.SUPPRESS)
    gu = sub.add_parser("gui", help="Fenster: Tunnel, Live-Anzeige, Import, Sicherung")
    gu.add_argument("--data", default="")
    gu.add_argument("--selbsttest", type=float, default=0, help=argparse.SUPPRESS)
    tu = sub.add_parser("tunnel", help="Tunnel verwalten (Administrator)")
    tu.add_argument("action", choices=["list", "import", "import-qr", "connect", "disconnect", "default", "rename", "delete", "home"])
    tu.add_argument("name", nargs="?", default="", help="Tunnel bzw. Datei/Bild beim Import")
    tu.add_argument("new", nargs="?", default="", help="neuer Name (rename) bzw. Name beim Import")
    tu.add_argument("--connect", action="store_true", help="nach dem Import verbinden")
    tu.add_argument("--networks", default="", help="home: eigene Heimnetze, z. B. 192.168.99.0/24 (leer = aus AllowedIPs)")
    tu.add_argument("--check", default="", help="home: eigene Prüfadresse host:port (leer = VERA)")
    tu.add_argument("--data", default="")
    bk = sub.add_parser("backup", help="Sicherung in VERA (Administrator; Kennwort aus VC_BACKUP_PASSPHRASE oder Abfrage)")
    bk.add_argument("action", choices=["create", "list", "restore", "delete"])
    bk.add_argument("id", nargs="?", type=int, default=0)
    bk.add_argument("--comment", default="")
    bk.add_argument("--settings", action="store_true", help="beim Wiederherstellen auch die Adressen übernehmen")
    bk.add_argument("--data", default="")
    qd = sub.add_parser("qr-decode", help="QR-Code in einem Bild lesen und Text ausgeben")
    qd.add_argument("image")
    ac = sub.add_parser("admin-cmd", help=argparse.SUPPRESS)
    ac.add_argument("request")
    ac.add_argument("--data", default="")
    if argv[0] == "uninstall":                                   # also "uninstall /S" (Apps & Features, quiet)
        argv = ["uninstall"] + ["--silent" if x.upper() in ("/S", "/SILENT", "/QUIET") else x for x in argv[1:]]
    a = ap.parse_args(argv)
    if a.cmd == "install":
        p = {"URL": a.url, "ENROLLKEY": a.enroll_key, "UPDATEURL": a.update_url, "UPDATEKEY": a.update_key, "TUNNEL": a.tunnel,
             "silent": a.silent}
        install({k: v for k, v in p.items() if v})
        print(f"{APP} installiert.")
    elif a.cmd == "uninstall":
        uninstall(a.silent)
    elif a.cmd == "status":
        import winservice
        print(winservice.status())
        print(json.dumps(load("status.json"), indent=2, ensure_ascii=False))
    elif a.cmd == "diagnose":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
        rep = diagnose()
        print(rep)
        if a.out:
            open(a.out, "w", encoding="utf-8-sig").write(rep)
    elif a.cmd == "embedded":
        e = embedded_config()
        print(json.dumps({k: ("…" if "KEY" in k and v else v) for k, v in e.items()}, ensure_ascii=False) if e else "keine eingebauten Einstellungen")
    elif a.cmd == "version":
        print(VERSION)
    elif a.cmd == "configure":
        configure()
    elif a.cmd == "upgrade":
        upgrade(a.target)
    elif a.cmd == "tray":
        import tray
        sys.exit(tray.run(a.data or DATA, a.selbsttest))
    elif a.cmd == "gui":
        import gui
        sys.exit(gui.run(a.data or DATA, a.selbsttest))
    elif a.cmd in ("tunnel", "backup", "admin-cmd"):
        DATA = a.data or DATA
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
        try:
            if a.cmd == "admin-cmd":
                admin_cmd(a.request)
            else:
                {"tunnel": cli_tunnel, "backup": cli_backup}[a.cmd](a)
        except (wgconf.ConfError, OSError) as e:
            raise SystemExit(f"Fehler: {e}") from e
    elif a.cmd == "qr-decode":
        import qrdecode
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
        try:
            print(qrdecode.decode_file(a.image))
        except qrdecode.QRError as e:
            raise SystemExit(f"Kein QR-Code lesbar: {e}") from e
    elif a.cmd == "run":
        DATA = a.data or DATA
        SIMULATE = a.simulate
        if WIN and a.service:
            import winservice
            try:
                sys.stdout = sys.stderr = open(_path("connect.out"), "a", encoding="utf-8", buffering=1)
                winservice.run_as_service(lambda: Agent().loop(), STOP)
            except BaseException:
                import traceback
                with open(_path("connect-crash.txt"), "a", encoding="utf-8") as f:
                    f.write(time.strftime("%Y-%m-%d %H:%M:%S\n") + traceback.format_exc() + "\n")
                raise
        else:
            try:
                Agent().loop()
            except KeyboardInterrupt:
                STOP.set()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
