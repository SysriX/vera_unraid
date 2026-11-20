"""Fake OPNsense API (WireGuard + firewall automation) for local tests. Usage: mock_opnsense.py PORT SITE"""
import base64, sys, time, uuid
from fastapi import FastAPI, Request, HTTPException
import uvicorn

PORT, SITE = int(sys.argv[1]), sys.argv[2]
KEY, SECRET = "testkey", "testsecret"
app = FastAPI()
net = "10.10.10" if SITE == "a" else "10.20.20"
S = {"servers": {}, "clients": {}, "rules": {}, "aliases": {}, "reconfigs": 0, "applied": 0}

def u(): return str(uuid.uuid4())
def k(): return base64.b64encode(uuid.uuid4().bytes * 2).decode()

c1, c2 = u(), u()
S["clients"][c1] = {"enabled": "1", "name": "iPhone_Max", "pubkey": k(), "psk": "", "tunneladdress": f"{net}.2/32", "serveraddress": "", "serverport": "", "keepalive": ""}
S["clients"][c2] = {"enabled": "1", "name": "Laptop_Anna", "pubkey": k(), "psk": k(), "tunneladdress": f"{net}.3/32", "serveraddress": "", "serverport": "", "keepalive": ""}
S["servers"][u()] = {"enabled": "1", "name": "RoadWarrior", "instance": "0", "pubkey": k(), "privkey": k(), "port": "51820",
                     "tunneladdress": f"{net}.1/24", "mtu": "", "dns": "192.168.0.1", "disableroutes": "0", "gateway": "", "peers": f"{c1},{c2}"}

def auth(req: Request):
    h = req.headers.get("authorization", "")
    if h != "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode():
        raise HTTPException(401, "auth")

def opt_list(csv, names):
    return {x: {"value": names.get(x, x), "selected": 1} for x in csv.split(",") if x}

@app.get("/api/wireguard/server/get")
def sget(req: Request):
    auth(req)
    names = {cu: c["name"] for cu, c in S["clients"].items()}
    out = {}
    for su, s in S["servers"].items():
        d = dict(s); d["peers"] = {**{cu: {"value": n, "selected": 0} for cu, n in names.items()}, **opt_list(s["peers"], names)}
        d["tunneladdress"] = opt_list(s["tunneladdress"], {})
        d["enabled"] = s["enabled"]
        out[su] = d
    return {"server": {"servers": {"server": out}}}

@app.get("/api/wireguard/client/get")
def cget(req: Request):
    auth(req)
    out = {}
    for cu, c in S["clients"].items():
        d = dict(c); d["tunneladdress"] = opt_list(c["tunneladdress"], {}); out[cu] = d
    return {"client": {"clients": {"client": out}}}

def validate(kind, d):
    v = {}
    if "name" in d and (not d["name"] or any(ch not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-" for ch in d["name"])):
        v[f"{kind}.name"] = "Ungültiger Name"
    if kind == "server" and "peers" in d:
        for p in [x for x in d["peers"].split(",") if x]:
            if p not in S["clients"]: v["server.peers"] = "unbekannter Peer"
    return v

@app.post("/api/wireguard/{kind}/{action}")
@app.post("/api/wireguard/{kind}/{action}/{uid}")
async def wg_action(kind: str, action: str, req: Request, uid: str = ""):
    auth(req)
    if kind == "service" and action == "reconfigure":
        S["reconfigs"] += 1; return {"status": "ok"}
    store = S["servers"] if kind == "server" else S["clients"]
    body = {}
    try: body = (await req.json()).get(kind, {})
    except Exception: pass
    if action.startswith("add"):
        v = validate(kind, body)
        if v: return {"result": "failed", "validations": v}
        n = u(); store[n] = {**body}
        if kind == "server": store[n].setdefault("instance", str(len(S["servers"]) - 1))
        return {"result": "saved", "uuid": n}
    if action.startswith("set"):
        if uid not in store: return {"result": "failed"}
        v = validate(kind, body)
        if v: return {"result": "failed", "validations": v}
        store[uid].update(body); return {"result": "saved"}
    if action.startswith("del"):
        if uid in store:
            del store[uid]; return {"result": "deleted"}
        return {"result": "not found"}
    return {"result": "failed"}

@app.get("/api/wireguard/service/show")
def show(req: Request):
    auth(req)
    rows = []
    for i, (cu, c) in enumerate(S["clients"].items()):
        rows.append({"type": "peer", "public-key": c["pubkey"], "endpoint": f"203.0.113.{i+5}:4{i}000",
                     "latest-handshake": int(time.time()) - (30 if i == 0 else 7200), "transfer-rx": 1234567 * (i + 1), "transfer-tx": 7654321})
    return {"rows": rows}

@app.post("/api/firewall/filter/{action}")
@app.post("/api/firewall/filter/{action}/{uid}")
async def filt(action: str, req: Request, uid: str = ""):
    auth(req)
    if action == "addRule":
        n = u(); S["rules"][n] = (await req.json())["rule"]; return {"result": "saved", "uuid": n}
    if action == "delRule":
        S["rules"].pop(uid, None); return {"result": "deleted"}
    if action == "savepoint": return {"revision": "12345.67"}
    if action == "apply": S["applied"] += 1; return {"status": "OK"}
    if action == "cancelRollback": return {"status": "ok"}
    return {}

@app.post("/api/firewall/alias/{action}")
@app.post("/api/firewall/alias/{action}/{uid}")
async def alias(action: str, req: Request, uid: str = ""):
    auth(req)
    if action == "addItem":
        n = u(); S["aliases"][n] = (await req.json())["alias"]; return {"result": "saved", "uuid": n}
    if action == "delItem":
        S["aliases"].pop(uid, None); return {"result": "deleted"}
    return {"status": "ok"}

@app.get("/_state")
def state(): return S

uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
