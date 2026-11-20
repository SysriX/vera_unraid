"""Helper for the Windows test of VERA-Connect (GitHub Actions, .github/workflows/connect-windows.yml).

    python tools/connect_ci.py setup                  VERA: first admin, firewall (mock OPNsense on 18101), import
    python tools/connect_ci.py approve <hostname>     wait until the computer waits for approval, approve with a new peer
    python tools/connect_ci.py check <hostname>       VERA has the report of the client (WireGuard version, tunnel state)
VERA runs on http://127.0.0.1:18110 with setup code CI-TEST.
"""
import sys
import time

import httpx

V = "http://127.0.0.1:18110"
c = httpx.Client(base_url=V, headers={"X-VERA": "1"}, timeout=30)


def ok(r):
    if r.status_code >= 400:
        print("FEHLER", r.status_code, r.text[:400])
        sys.exit(1)
    return r.json()


def login():
    ok(c.post("/api/login", json={"username": "admin", "password": "ci-admin-password"}))


def wait(fn, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        x = fn()
        if x:
            return x
        time.sleep(3)
    print("Zeitüberschreitung:", what)
    sys.exit(1)


cmd = sys.argv[1]
if cmd == "setup":
    ok(c.post("/api/setup", json={"code": "CI-TEST", "username": "admin", "password": "ci-admin-password"}))
    fw = ok(c.post("/api/firewalls", json={"name": "OPN CI", "url": "http://127.0.0.1:18101", "api_key": "testkey", "api_secret": "testsecret",
                                           "site_name": "CI", "endpoint_host": "127.0.0.1", "client_allowed_ips": "10.10.10.0/24"}))
    print(ok(c.post(f"/api/wg/{fw['id']}/sync")))
elif cmd == "approve":
    login()
    host = sys.argv[2].upper()
    cl = wait(lambda: [x for x in ok(c.get("/api/clients"))["clients"] if x["hostname"].upper() == host and x["status"] == "pending"],
              180, "Rechner meldet sich nicht")[0]
    print("Wartet auf Freigabe:", cl["hostname"], cl["os"], cl["username"])
    fw = ok(c.get("/api/firewalls"))["firewalls"][0]
    inst = [i for i in ok(c.get(f"/api/wg/{fw['id']}/overview?status=0"))["instances"] if i["role"] == "clients"][0]
    print(ok(c.post(f"/api/clients/{cl['id']}/approve", json={"firewall_id": fw["id"], "mode": "new", "instance_id": inst["id"],
                                                              "name": cl["hostname"], "tunnel": "CI"})))
elif cmd == "check":
    login()
    host = sys.argv[2].upper()
    cl = wait(lambda: [x for x in ok(c.get("/api/clients"))["clients"] if x["hostname"].upper() == host and x["wg_version"]
                       and x["report"].get("tunnel_state") not in (None, "waiting", "missing")], 600, "kein Bericht mit WireGuard")[0]
    print("Bericht:", cl["client_version"], "WireGuard", cl["wg_version"], cl["report"])
    print("Verlauf:", [h["e"] for h in cl["history"]][:10])
