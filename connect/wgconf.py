"""WireGuard configurations for VERA-Connect – standard library only.

    parse(text) -> dict            sections + check (raises ConfError with a German reason)
    summary(text) -> dict          address, DNS, peers (endpoint, allowed IPs), public key, full tunnel?
    keypair() -> (private, public) X25519 (RFC 7748), base64 like `wg genkey | wg pubkey`
    template(private_b64) -> str   new configuration to fill in
    seal(data, passphrase) / unseal(blob, passphrase)   encryption of backups (see below)
    safe_name(text) -> str         valid tunnel name for WireGuard for Windows
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets

NAME_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,32}$")


class ConfError(ValueError):
    pass


def safe_name(text: str, fallback: str = "Tunnel") -> str:
    n = re.sub(r"[^A-Za-z0-9_=+.-]", "", (text or "").replace(" ", "-"))[:32]
    return n or fallback


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name or ""))


def _key(v: str) -> bool:
    try:
        return len(base64.b64decode(v.strip(), validate=True)) == 32
    except (ValueError, TypeError):
        return False


def parse(text: str) -> dict:
    """{"interface": {key: value}, "peers": [{key: value}]}. Keys as written (case kept), values stripped."""
    if not text or len(text) > 64_000:
        raise ConfError("Leere oder zu große Konfiguration")
    iface: dict | None = None
    peers: list[dict] = []
    cur = None
    for n, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low == "[interface]":
            if iface is not None:
                raise ConfError(f"Zeile {n}: [Interface] doppelt")
            iface = {}
            cur = iface
            continue
        if low == "[peer]":
            cur = {}
            peers.append(cur)
            continue
        if line.startswith("["):
            raise ConfError(f"Zeile {n}: unbekannter Abschnitt {line}")
        if cur is None or "=" not in line:
            raise ConfError(f"Zeile {n}: „{line[:40]}“ ist keine gültige Zeile")
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        key = k.lower()
        if key in ("allowedips", "address", "dns") and k in cur:      # may appear several times
            cur[k] = cur[k] + ", " + v
        else:
            cur[k] = v
    if iface is None:
        raise ConfError("Abschnitt [Interface] fehlt – ist das eine WireGuard-Konfiguration?")
    lower = {k.lower(): v for k, v in iface.items()}
    if not _key(lower.get("privatekey", "")):
        raise ConfError("PrivateKey fehlt oder ist ungültig")
    if not peers:
        raise ConfError("Kein [Peer] in der Konfiguration")
    for i, p in enumerate(peers, 1):
        pl = {k.lower(): v for k, v in p.items()}
        if not _key(pl.get("publickey", "")):
            raise ConfError(f"Peer {i}: PublicKey fehlt oder ist ungültig")
        if pl.get("presharedkey") and not _key(pl["presharedkey"]):
            raise ConfError(f"Peer {i}: PresharedKey ist ungültig")
        if not pl.get("allowedips"):
            raise ConfError(f"Peer {i}: AllowedIPs fehlt")
    return {"interface": iface, "peers": peers}


def _get(d: dict, key: str) -> str:
    return next((v for k, v in d.items() if k.lower() == key), "")


def _split(v: str) -> list[str]:
    return [x.strip() for x in v.split(",") if x.strip()]


def summary(text: str) -> dict:
    c = parse(text)
    i = c["interface"]
    peers = [{"public_key": _get(p, "publickey"), "endpoint": _get(p, "endpoint"), "allowed_ips": _split(_get(p, "allowedips")),
              "keepalive": _get(p, "persistentkeepalive")} for p in c["peers"]]
    allowed = [a for p in peers for a in p["allowed_ips"]]
    return {"address": _split(_get(i, "address")), "dns": _split(_get(i, "dns")), "peers": peers,
            "public_key": public_key(_get(i, "privatekey")), "full_tunnel": any(a in ("0.0.0.0/0", "::/0") for a in allowed),
            "keepalive": any(p["keepalive"] and p["keepalive"] != "0" for p in peers)}


def full_tunnel(text: str) -> bool:
    try:
        return summary(text)["full_tunnel"]
    except ConfError:
        return False


# ------------------------------------------------------------------ X25519 (RFC 7748)
_P = 2 ** 255 - 19
_A24 = 121665


def _x25519(k: bytes, u: bytes) -> bytes:
    kn = bytearray(k)
    kn[0] &= 248
    kn[31] &= 127
    kn[31] |= 64
    k_int = int.from_bytes(kn, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def public_key(private_b64: str) -> str:
    try:
        k = base64.b64decode(private_b64.strip(), validate=True)
    except (ValueError, TypeError):
        return ""
    if len(k) != 32:
        return ""
    return base64.b64encode(_x25519(k, (9).to_bytes(32, "little"))).decode()


def keypair() -> tuple[str, str]:
    k = bytearray(secrets.token_bytes(32))
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    priv = base64.b64encode(bytes(k)).decode()
    return priv, public_key(priv)


def template(private_b64: str) -> str:
    return (f"[Interface]\nPrivateKey = {private_b64}\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n"
            "[Peer]\nPublicKey = <öffentlicher Schlüssel der Gegenstelle>\nAllowedIPs = 10.0.0.0/24\n"
            "Endpoint = vpn.example.org:51820\nPersistentKeepalive = 25\n")


# ------------------------------------------------------------------ backup encryption
# PBKDF2-HMAC-SHA256 (600 000 rounds) derives two keys from the passphrase; the content is encrypted with
# HMAC-SHA256 in counter mode (a PRF used as stream cipher) and authenticated with HMAC-SHA256 over everything
# (encrypt-then-MAC). Standard library only; VERA stores the sealed blob and never sees the passphrase.
SEAL_FORMAT = "vera-connect-sealed-1"
ROUNDS = 600_000


def _keys(passphrase: str, salt: bytes, rounds: int) -> tuple[bytes, bytes]:
    k = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, rounds, 64)
    return k[:32], k[32:]


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hmac.new(key, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
        i += 1
    return bytes(out[:n])


def seal(data: dict, passphrase: str) -> str:
    if len(passphrase or "") < 8:
        raise ConfError("Kennwort für die Sicherung: mindestens 8 Zeichen")
    pt = json.dumps(data, ensure_ascii=False).encode("utf-8")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    ek, mk = _keys(passphrase, salt, ROUNDS)
    ct = bytes(a ^ b for a, b in zip(pt, _stream(ek, nonce, len(pt))))
    head = f"{SEAL_FORMAT}|{ROUNDS}|".encode()
    tag = hmac.new(mk, head + salt + nonce + ct, hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return json.dumps({"format": SEAL_FORMAT, "rounds": ROUNDS, "salt": b(salt), "nonce": b(nonce), "data": b(ct), "tag": b(tag)})


def unseal(blob: str, passphrase: str) -> dict:
    try:
        d = json.loads(blob)
        if d.get("format") != SEAL_FORMAT:
            raise ConfError("Unbekanntes Format der Sicherung")
        rounds = int(d["rounds"])
        salt, nonce, ct, tag = (base64.b64decode(d[k]) for k in ("salt", "nonce", "data", "tag"))
    except (ValueError, KeyError, TypeError) as e:
        raise ConfError("Sicherung beschädigt") from e
    if not 100_000 <= rounds <= 10_000_000:
        raise ConfError("Sicherung beschädigt")
    ek, mk = _keys(passphrase or "", salt, rounds)
    head = f"{SEAL_FORMAT}|{rounds}|".encode()
    if not hmac.compare_digest(tag, hmac.new(mk, head + salt + nonce + ct, hashlib.sha256).digest()):
        raise ConfError("Kennwort falsch (oder Sicherung verändert)")
    pt = bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct))))
    return json.loads(pt.decode("utf-8"))
