#!/usr/bin/env python3
"""VERA-Connect – keeps the WireGuard tunnel of a Windows computer configured, connected and up to date.

    VERA-Connect-Setup.exe                                         install (asks for the address of VERA)
    VERA-Connect-Setup.exe /S URL=https://<VERA_EXTERN> ENROLLKEY=vk_… UPDATEURL=https://<UPDATE_URL> [UPDATEKEY=…] [TUNNEL=…]
    vera-connect.exe install --url … [--enroll-key …] [--update-url …] [--update-key …] [--tunnel …] [--silent]
    vera-connect.exe uninstall | status | version | configure | tray
    vera-connect.exe run [--data DIR] [--simulate]              foreground (the service runs this); --simulate = no WireGuard changes

What the service (LocalSystem) does:
  1. device identity: machine id (SMBIOS UUID + MachineGuid + BIOS serial, hashed) and an Ed25519 device key (DPAPI)
  2. POST <VERA>/client/enroll → unknown computers wait in VERA for approval (checks again every minute)
  3. approved → fetch the configuration, keep an encrypted copy, install WireGuard if missing (official MSI, signature checked),
     register the tunnel as a Windows service, switch off WireGuard's own tray/manager
  4. watchdog every 30 s: tunnel missing → restore, no handshake for 3 min → restart (with growing pauses)
  5. VERA changes the configuration (new keys, networks) → new configuration is installed automatically
  6. daily: newer WireGuard → install; every 6 h: newer VERA-Connect in UMA (signed) → update itself
The user may disconnect in the tray (if VERA allows it); it stays off until "Verbinden" or the next restart of Windows.
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

import ed25519

VERSION = "1.1.3"
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
            return STATUS.get("sim_state", "RUNNING")
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
            STATUS["sim_state"] = "RUNNING"
            log("[simuliert] Tunnel", name, "eingerichtet")
            return
        c, o = run([self.exe, "/installtunnelservice", p], 120)
        if c != 0:
            raise RuntimeError(f"Tunnel einrichten fehlgeschlagen ({c}): {o[-300:]}")
        log("Tunnel", name, "eingerichtet")

    def remove_tunnel(self, name: str) -> None:
        if SIMULATE:
            STATUS["sim_state"] = "MISSING"
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
            STATUS["sim_state"] = "RUNNING"
            return
        run(["sc.exe", "start", self.service(name)], 60)

    def stop(self, name: str) -> None:
        if SIMULATE:
            STATUS["sim_state"] = "STOPPED"
            return
        run(["sc.exe", "stop", self.service(name)], 60)

    def stats(self, name: str) -> dict:
        """latest handshake (unix time) and transfer of the tunnel."""
        if SIMULATE:
            return {"last_handshake": int(time.time()) - 20, "rx": 1234, "tx": 567}
        out = {}
        c, o = run([self.wg, "show", name, "latest-handshakes"], 30)
        if c == 0:
            hs = [int(x.split()[-1]) for x in o.splitlines() if x.strip() and x.split()[-1].isdigit()]
            out["last_handshake"] = max(hs) if hs else 0
        c, o = run([self.wg, "show", name, "transfer"], 30)
        if c == 0:
            rx = tx = 0
            for line in o.splitlines():
                p = line.split()
                if len(p) >= 3 and p[-1].isdigit() and p[-2].isdigit():
                    rx, tx = rx + int(p[-2]), tx + int(p[-1])
            out.update(rx=rx, tx=tx)
        return out


# ------------------------------------------------------------------ the service loop
def boot_time() -> int:
    if WIN:
        return int(time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000) // 60 * 60
    return 0


class Agent:
    def __init__(self):
        _load_extra_ca()
        self.dev = Device()
        self.wg = WireGuard()
        self.state = load("state.json")
        self.events: list[str] = []
        self.next_poll = self.next_wg = self.next_self = 0.0
        self.uma_wg = None
        self.restart_pause, self.next_restart, self.tunnel_started = 60, 0.0, time.time()
        if self.state.get("user_off") and self.state.get("user_off_boot") != boot_time():
            self.state["user_off"] = False                     # a restart of Windows reconnects
            log("Windows neu gestartet – Tunnel wird wieder verbunden")
        if self.state.get("user_off") is None:
            self.state["user_off"] = False

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

    def report(self) -> dict:
        f = self.dev.refresh_facts()
        t = self.state.get("tunnel")
        st = {"version": VERSION, "wg_version": self.wg.version(), "wg_source": STATUS.get("wg_source", ""), "hostname": f.get("hostname"), "user": f.get("user") or "",
              "os": f.get("os"), "user_off": bool(self.state.get("user_off")), "tunnel_state": STATUS.get("tunnel_state", "waiting")}
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
            set_status(server_ok=time.time(), allow_disconnect=bool(r.get("allow_disconnect", True)), vera=c["url"])
            self.next_poll = time.time() + (POLL_MIN if os.environ.get("VC_FAST") else max(POLL_MIN, int(r.get("interval") or 60)))
            st = r.get("status")
            if st == "pending":
                set_status(state="pending", message="wartet auf Freigabe in VERA")
            elif st == "blocked":
                if self.state.get("tunnel"):
                    self.wg.remove_tunnel(self.state["tunnel"])
                    self.event("In VERA gesperrt – Tunnel entfernt")
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

    def fetch_and_apply(self) -> None:
        r = request(self.dev, self.conf["url"], "POST", "/client/config", {})
        name = re.sub(r"[^A-Za-z0-9_=+.-]", "", self.conf.get("tunnel") or r.get("tunnel") or "VERA")[:32] or "VERA"
        text = r["text"]
        self.ensure_wireguard()
        old = self.state.get("tunnel")
        if old and old != name:
            self.wg.remove_tunnel(old)
        self.wg.install_tunnel(name, text)
        self.state.update(tunnel=name, config=protect(text.encode()), config_hash=r["hash"])
        self.keep()
        self.tunnel_started, self.restart_pause = time.time(), 60
        if self.state.get("user_off"):
            self.wg.stop(name)
        self.event(f"Neue Konfiguration eingerichtet (Tunnel {name})")
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
        t = self.state.get("tunnel")
        if t and have and not self.state.get("user_off") and self.wg.svc_state(t) != "RUNNING":
            self.wg.start(t)
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
                t = self.state.get("tunnel")
                if t and not self.state.get("user_off") and self.wg.svc_state(t) != "RUNNING":
                    self.wg.start(t)
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
            subprocess.Popen([new, "upgrade", "--target", target], stdin=subprocess.DEVNULL, close_fds=True,
                             creationflags=0x00000008 | 0x00000200 | 0x01000000 | NOWIN)   # detached, new group, breakaway
        except HttpError as e:
            log("Update-Server:", e)
            set_status(update_state=f"Fehler: {e.detail}")
            self.next_self = time.time() + 3600
        except Exception as e:  # noqa: BLE001
            log("Selbst-Update:", e)
            set_status(update_state=f"Fehler: {e}")
            self.next_self = time.time() + 3600

    # ----- watchdog
    def watch(self) -> None:
        t = self.state.get("tunnel")
        if not t:
            set_status(tunnel_state="waiting")
            return
        if take_flag("disconnect.flag") and STATUS.get("allow_disconnect", True):
            self.state.update(user_off=True, user_off_boot=boot_time())
            self.keep()
            self.wg.stop(t)
            self.event("Vom Benutzer getrennt")
        if take_flag("connect.flag") and self.state.get("user_off"):
            self.state["user_off"] = False
            self.keep()
            self.wg.start(t)
            self.tunnel_started, self.restart_pause = time.time(), 60
            self.event("Vom Benutzer verbunden")
        s = self.wg.svc_state(t)
        if s == "MISSING":                                        # deleted by someone / config lost
            text = self.cached_config()
            if text:
                try:
                    self.ensure_wireguard()
                    self.wg.install_tunnel(t, text)
                    self.tunnel_started = time.time()
                    self.event("Tunnel fehlte – aus gespeicherter Konfiguration wiederhergestellt")
                    if self.state.get("user_off"):
                        self.wg.stop(t)
                except Exception as e:  # noqa: BLE001
                    set_status(tunnel_state="missing", last_error=str(e)[:300])
                    log("Wiederherstellen:", e)
                    return
            else:
                self.state["config_hash"] = ""                    # fetch again at the next poll
                self.next_poll = 0
                set_status(tunnel_state="missing")
                return
        if self.state.get("user_off"):
            if s == "RUNNING":
                self.wg.stop(t)
            set_status(tunnel_state="user_off", state="user_off")
            return
        if s != "RUNNING":
            if time.time() >= self.next_restart:
                self.wg.start(t)
                self.tunnel_started = time.time()
                self.event("Tunnel war aus – neu gestartet")
                self.next_restart = time.time() + 30
            set_status(tunnel_state="down", state="down")
            return
        hs = self.wg.stats(t).get("last_handshake") or 0
        age = time.time() - hs if hs else None
        if age is not None and age <= HANDSHAKE_MAX:
            self.restart_pause = 60
            set_status(tunnel_state="up", state="up", last_handshake=hs, message="")
            return
        set_status(tunnel_state="down", state="down", last_handshake=hs)
        if time.time() - self.tunnel_started < HANDSHAKE_MAX or time.time() < self.next_restart:
            return
        if not internet_ok():
            set_status(message="kein Internet – warte")
            return
        log(f"Kein Handshake seit {int(age) if age else 'Start'} s – Tunnel wird neu verbunden (nächster Versuch frühestens in {self.restart_pause // 60} min)")
        self.wg.stop(t)
        time.sleep(2)
        self.wg.start(t)
        self.tunnel_started = time.time()
        self.next_restart = time.time() + self.restart_pause
        self.restart_pause = min(self.restart_pause * 2, 1800)
        self.events.append("Tunnel ohne Verbindung – neu verbunden")

    def loop(self) -> None:
        log(f"{APP} {VERSION} startet (Daten: {DATA}{', SIMULATION' if SIMULATE else ''})")
        set_status(state="start", message="", tunnel=self.state.get("tunnel"), vera=self.conf.get("url", ""),
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
                if time.time() >= self.next_wg and self.state.get("tunnel"):
                    self.wireguard_update()
                if time.time() >= self.next_self:
                    self.self_update()
            except Exception as e:  # noqa: BLE001 – the service must never die
                import traceback
                log("Fehler:", e, traceback.format_exc()[-800:])
                set_status(last_error=str(e)[:300])
            end = time.time() + WATCH_EVERY
            while not STOP.is_set() and time.time() < end:
                if any(os.path.exists(os.path.join(DATA, "ui", f)) for f in ("connect.flag", "disconnect.flag", "refresh.flag")):
                    break
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
        try:
            t0 = time.time()
            socket.create_connection((host, port), timeout=10).close()
            out.append(f"  2. Port {port} erreichbar ({int((time.time() - t0) * 1000)} ms)")
        except OSError as e:
            out.append(f"  2. Port {port} NICHT erreichbar: {e}  → Weiterleitung/Firewall/Proxy prüfen")
            continue
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
    if p.get("UPDATEURL"):
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
            for _ in range(10):
                try:
                    shutil.copy2(me, target)
                    break
                except OSError:
                    time.sleep(1)
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
        subprocess.Popen([exe_path(), "tray"], stdin=subprocess.DEVNULL, close_fds=True, creationflags=0x00000008 | 0x00000200)
    except OSError as e:
        log("Tray-Start:", e)


def uninstall(silent: bool) -> None:
    import winservice
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("Bitte als Administrator ausführen.")
    if not silent and ctypes.windll.user32.MessageBoxW(None, "VERA-Connect entfernen? Der WireGuard-Tunnel dieses Rechners wird dabei ebenfalls entfernt. "
                                                       "WireGuard selbst bleibt installiert.", APP, 0x34) != 6:
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
    if st.get("tunnel"):
        WireGuard().remove_tunnel(st["tunnel"])
    for f in ("state.json", "status.json"):
        try:
            os.remove(_path(f))
        except OSError:
            pass
    _reg(UNINSTALL_KEY, None)
    log(f"{APP} entfernt (Geräteschlüssel bleibt – bei Neuinstallation erkennt VERA den Rechner wieder)")
    if COMPILED and os.path.isdir(home_dir()):
        subprocess.Popen(f'cmd.exe /c ping -n 4 127.0.0.1 >nul & rmdir /s /q "{home_dir()}"', stdin=subprocess.DEVNULL, close_fds=True,
                         creationflags=0x00000008 | NOWIN)
    if not silent:
        box("VERA-Connect wurde entfernt.")


def upgrade(target: str) -> None:
    """Run from the downloaded new exe: stop the service, replace the installed exe, start the service."""
    import winservice
    log(f"Selbst-Update auf {VERSION}: ersetze {target}")
    winservice.stop()
    me = os.path.abspath(sys.argv[0])
    for _ in range(30):
        try:
            shutil.copy2(me, target)
            break
        except OSError:
            time.sleep(1)
    else:
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
    p = parse_params(argv)
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
    sub.add_parser("configure")
    g = sub.add_parser("upgrade", help=argparse.SUPPRESS)
    g.add_argument("--target", required=True)
    t = sub.add_parser("tray")
    t.add_argument("--data", default="")
    t.add_argument("--selbsttest", type=float, default=0, help=argparse.SUPPRESS)
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
    elif a.cmd == "version":
        print(VERSION)
    elif a.cmd == "configure":
        configure()
    elif a.cmd == "upgrade":
        upgrade(a.target)
    elif a.cmd == "tray":
        import tray
        sys.exit(tray.run(a.data or DATA, a.selbsttest))
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
