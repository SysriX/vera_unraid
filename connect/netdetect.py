"""Home network detection for VERA-Connect ("trusted network detection") – standard library only.

    local_ipv4(exclude_ips)            -> [(ip, prefix, adapter)]   IPv4 of adapters that are up, without WireGuard/Wintun
    networks_of(summary, override)     -> [IPv4Network]             networks a tunnel reaches (AllowedIPs without /0) or the override
    match(local, networks)             -> (ip, network) | None      a local address inside one of them
    probe_vera(url, source_ip, ctx)    -> dict | None               /.well-known/sysrix-app of VERA, sent from that local address
    probe_tcp(host, port, source_ip)   -> bool                      plain TCP check (own check address without VERA)

A match alone is not enough (a hotel can use 192.168.99.0/24 as well): the tunnel is only paused if the check address –
by default VERA itself – answers *through the local adapter* (source address bound, Windows sends from the interface
that owns it) and, for VERA, with the instance id VERA-Connect knows from the normal connection.
"""
from __future__ import annotations

import ctypes
import http.client
import ipaddress
import json
import os
import socket
import ssl
from urllib.parse import urlsplit

SIM_FILE = "sim-local-ips.txt"                      # simulation: one "ip/prefix" per line in the data folder


class _IpAddrRow(ctypes.Structure):
    _fields_ = [("dwAddr", ctypes.c_uint32), ("dwIndex", ctypes.c_uint32), ("dwMask", ctypes.c_uint32), ("dwBCastAddr", ctypes.c_uint32),
                ("dwReasmSize", ctypes.c_uint32), ("unused1", ctypes.c_uint16), ("wType", ctypes.c_uint16)]


class _IfRow(ctypes.Structure):
    _fields_ = [("wszName", ctypes.c_wchar * 256), ("dwIndex", ctypes.c_uint32), ("dwType", ctypes.c_uint32), ("dwMtu", ctypes.c_uint32),
                ("dwSpeed", ctypes.c_uint32), ("dwPhysAddrLen", ctypes.c_uint32), ("bPhysAddr", ctypes.c_ubyte * 8),
                ("dwAdminStatus", ctypes.c_uint32), ("dwOperStatus", ctypes.c_uint32), ("dwLastChange", ctypes.c_uint32),
                ("dwInOctets", ctypes.c_uint32), ("dwInUcastPkts", ctypes.c_uint32), ("dwInNUcastPkts", ctypes.c_uint32),
                ("dwInDiscards", ctypes.c_uint32), ("dwInErrors", ctypes.c_uint32), ("dwInUnknownProtos", ctypes.c_uint32),
                ("dwOutOctets", ctypes.c_uint32), ("dwOutUcastPkts", ctypes.c_uint32), ("dwOutNUcastPkts", ctypes.c_uint32),
                ("dwOutDiscards", ctypes.c_uint32), ("dwOutErrors", ctypes.c_uint32), ("dwOutQLen", ctypes.c_uint32),
                ("dwDescrLen", ctypes.c_uint32), ("bDescr", ctypes.c_ubyte * 256)]


def _table(fn, row_type):
    size = ctypes.c_ulong(0)
    fn(None, ctypes.byref(size), False)
    buf = ctypes.create_string_buffer(size.value or 4)
    if fn(buf, ctypes.byref(size), False) != 0:
        return []
    n = ctypes.c_uint32.from_buffer(buf).value
    return list((row_type * n).from_buffer(buf, 4))


def _adapters() -> dict:
    """ifIndex -> (description, type, operational)."""
    out = {}
    for r in _table(ctypes.windll.iphlpapi.GetIfTable, _IfRow):
        descr = bytes(r.bDescr[:r.dwDescrLen]).rstrip(b"\0").decode("utf-8", "replace")
        out[r.dwIndex] = (descr, r.dwType, r.dwOperStatus in (4, 5))      # CONNECTED / OPERATIONAL
    return out


def local_ipv4(exclude_ips=(), data: str | None = None) -> list[tuple[str, int, str]]:
    if data and os.path.exists(os.path.join(data, SIM_FILE)):           # tests
        out = []
        for line in open(os.path.join(data, SIM_FILE), encoding="utf-8").read().split():
            n = ipaddress.ip_interface(line.strip())
            out.append((str(n.ip), n.network.prefixlen, "Simulation"))
        return out
    if os.name != "nt":
        return []
    ex = set(exclude_ips)
    ad = _adapters()
    out = []
    for r in _table(ctypes.windll.iphlpapi.GetIpAddrTable, _IpAddrRow):
        ip = socket.inet_ntoa(r.dwAddr.to_bytes(4, "little"))
        mask = socket.inet_ntoa(r.dwMask.to_bytes(4, "little"))
        descr, typ, up = ad.get(r.dwIndex, ("", 0, False))
        if not up or typ == 24 or ip.startswith(("127.", "169.254.", "0.")) or ip in ex:
            continue
        if "wireguard" in descr.lower() or "wintun" in descr.lower():
            continue
        out.append((ip, ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen, descr))
    return out


def networks_of(summary: dict, override=None) -> list:
    """Networks that identify the home network of a tunnel: the override, else its AllowedIPs (IPv4, not 0.0.0.0/0)."""
    src = override or [a for p in summary.get("peers", []) for a in p.get("allowed_ips", [])]
    nets = []
    for a in src:
        try:
            n = ipaddress.ip_network(str(a).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen >= (1 if override else 8) and (override or not n.is_loopback):
            nets.append(n)
    return nets


def match(local: list, networks: list):
    for ip, _, _ in local:
        a = ipaddress.ip_address(ip)
        for n in networks:
            if a in n:
                return ip, n
    return None


def probe_vera(url: str, source_ip: str, ctx: ssl.SSLContext | None = None, timeout: float = 4) -> dict | None:
    """GET <VERA>/.well-known/sysrix-app, sent from source_ip (so it leaves through the local adapter, not the tunnel)."""
    u = urlsplit(url)
    if not u.hostname:
        return None
    path = (u.path.rstrip("/") or "") + "/.well-known/sysrix-app"
    try:
        if u.scheme == "https":
            c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, source_address=(source_ip, 0), context=ctx)
        else:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout, source_address=(source_ip, 0))
        c.request("GET", path, headers={"User-Agent": "VERA-Connect"})
        r = c.getresponse()
        body = r.read(4000)
        c.close()
        if r.status != 200:
            return None
        d = json.loads(body)
        return d if isinstance(d, dict) and d.get("app") == "vera" else None
    except (OSError, ValueError, http.client.HTTPException):
        return None


def probe_tcp(host: str, port: int, source_ip: str, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout, source_address=(source_ip, 0)):
            return True
    except OSError:
        return False


def resolve4(host: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []
