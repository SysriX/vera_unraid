"""VERA-Connect – window for the logged-on user (tkinter, part of the EXE: `vera-connect.exe gui`).

    left     all tunnels (★ = default) with state · new / import .conf / import QR image / edit / rename / delete / default
    right    the selected tunnel live: state, endpoint, last handshake, received/sent with current rate + graph (3 min)
    bottom   backup in VERA: create (sealed with a passphrase), list of versions, restore, delete

Reading needs no rights: the service writes status.json (every 30 s) and – while this window is open, it touches
ui\\live.flag – live.json every second. Connect/disconnect go as flag files to ui\\ (any user, the VERA tunnel only if VERA
allows it). Everything else is a command in cmd\\ (administrators only): if this window runs without administrator
rights, each such action asks for them (UAC) through `vera-connect.exe admin-cmd`.
"""
from __future__ import annotations

import collections
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import wgconf

TITLE = "VERA-Connect"
STATE_TEXT = {"home": "im Heimnetz – pausiert", "up": "verbunden", "idle": "aktiv (Handshake erst bei Verkehr)", "connecting": "verbindet …", "down": "keine Verbindung",
              "missing": "fehlt – wird eingerichtet", "off": "getrennt"}
STATE_COLOR = {"home": "#2f7fd8", "up": "#2eb67d", "idle": "#2eb67d", "connecting": "#f0b428", "down": "#dc4646", "missing": "#dc4646", "off": "#8c919a"}
SERVICE_TEXT = {"home": "im Heimnetz – Tunnel pausiert", "up": "verbunden", "ready": "verbindet …", "down": "keine Verbindung – wird neu verbunden", "pending": "wartet auf Freigabe in VERA",
                "start": "startet", "installing": "richtet WireGuard ein", "user_off": "getrennt", "offline": "VERA nicht erreichbar",
                "error": "Fehler", "blocked": "in VERA gesperrt", "denied": "von VERA abgelehnt", "no_url": "Adresse von VERA fehlt",
                "dead": "Dienst läuft nicht"}
RX_COLOR, TX_COLOR = "#2eb67d", "#4d9fff"
HISTORY = 180


def _vc():
    m = sys.modules.get("__main__")
    if m is not None and hasattr(m, "send_command"):
        return m
    import vera_connect
    return vera_connect


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return True


def size(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return (f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}").replace(".", ",")
        n /= 1024
    return ""


def ago(t) -> str:
    if not t:
        return "noch keiner"
    d = int(time.time() - float(t))
    if d < 0:
        d = 0
    return f"vor {d} s" if d < 120 else f"vor {d // 60} min" if d < 7200 else f"vor {d // 3600} h"


def _exe_args(args: list[str]) -> tuple[str, str]:
    compiled = "__compiled__" in vars(sys.modules["__main__"]) or getattr(sys, "frozen", False)
    if compiled:
        return os.path.abspath(sys.argv[0]), subprocess.list2cmdline(args)
    return sys.executable, subprocess.list2cmdline([os.path.join(os.path.dirname(os.path.abspath(__file__)), "vera_connect.py"), *args])


class App:
    def __init__(self, data: str):
        self.data = data
        self.admin = is_admin()
        self.hist: dict[str, collections.deque] = {}
        self.prev: dict[str, tuple] = {}
        self.status: dict = {}
        self.live: dict = {}
        self.sel: str | None = None
        self.busy = 0
        self.last_touch = 0.0
        self.root = tk.Tk()
        self.root.title(TITLE)
        self.k = max(1.0, self.root.winfo_fpixels("1i") / 96)              # Windows display scaling (125 %, 150 % …)
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{min(int(1080 * self.k), int(sw * 0.92))}x{min(int(690 * self.k), int(sh * 0.88))}")
        self.root.minsize(int(860 * self.k), int(560 * self.k))
        self._icon()
        st = ttk.Style(self.root)
        if "vista" in st.theme_names():
            st.theme_use("vista")
        st.configure("H.TLabel", font=("Segoe UI", 13, "bold"))
        st.configure("T.TLabel", font=("Segoe UI", 11, "bold"))
        st.configure("K.TLabel", foreground="#5b6170")
        st.configure("Treeview", rowheight=self.px(22))
        self._build()
        self.tick()

    def px(self, n: float) -> int:
        return int(n * self.k)

    def _icon(self):
        try:
            import tray
            p = os.path.join(tempfile.gettempdir(), "vera-connect-window.ico")
            with open(p, "wb") as f:
                f.write(tray._ico((16, 32, 48), None))
            self.root.iconbitmap(default=p)
        except Exception:  # noqa: BLE001 – only cosmetics
            pass

    # ------------------------------------------------------------------ layout
    def _build(self):
        r = self.root
        top = ttk.Frame(r, padding=(12, 10, 12, 4))
        top.pack(fill="x")
        ttk.Label(top, text="VERA-Connect", style="H.TLabel").pack(side="left")
        self.svc = ttk.Label(top, text="", style="K.TLabel")
        self.svc.pack(side="left", padx=14)
        if not self.admin:
            ttk.Button(top, text="Als Administrator öffnen", command=self.reopen_admin).pack(side="right")
            ttk.Label(top, text="Verwalten fragt nach Administratorrechten", style="K.TLabel").pack(side="right", padx=8)
        pane = ttk.PanedWindow(r, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=12, pady=6)

        left = ttk.Frame(pane, padding=(0, 0, 8, 0))
        pane.add(left, weight=1)
        ttk.Label(left, text="Tunnel", style="T.TLabel").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("art", "zustand"), show="tree headings", height=12, selectmode="browse")
        self.tree.heading("#0", text="Name")
        self.tree.heading("art", text="Herkunft")
        self.tree.heading("zustand", text="Zustand")
        self.tree.column("#0", width=self.px(150))
        self.tree.column("art", width=self.px(70))
        self.tree.column("zustand", width=self.px(110))
        self.tree.pack(fill="both", expand=True, pady=(4, 6))
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._select())
        self.tree.bind("<Double-1>", lambda e: self.toggle())
        for c, col in STATE_COLOR.items():
            self.tree.tag_configure(c, foreground=col)
        b = ttk.Frame(left)
        b.pack(fill="x")
        self.btn_new = ttk.Button(b, text="Neu …", command=self.new_tunnel)
        self.btn_file = ttk.Button(b, text="Aus Datei (.conf) …", command=self.import_file)
        self.btn_qr = ttk.Button(b, text="Aus QR-Bild …", command=self.import_qr)
        self.btn_edit = ttk.Button(b, text="Bearbeiten …", command=self.edit_tunnel)
        self.btn_ren = ttk.Button(b, text="Umbenennen …", command=self.rename)
        self.btn_del = ttk.Button(b, text="Löschen", command=self.delete)
        self.btn_def = ttk.Button(b, text="Als Standard", command=self.make_default)
        self.btn_home = ttk.Button(b, text="Heimnetz …", command=self.home_dialog)
        for i, w in enumerate((self.btn_new, self.btn_file, self.btn_qr, self.btn_edit, self.btn_ren, self.btn_del, self.btn_def,
                               self.btn_home)):
            w.grid(row=i // 2, column=i % 2, sticky="ew", padx=2, pady=2)
        b.columnconfigure(0, weight=1)
        b.columnconfigure(1, weight=1)

        right = ttk.Frame(pane, padding=(8, 0, 0, 0))
        pane.add(right, weight=3)
        head = ttk.Frame(right)
        head.pack(fill="x")
        self.title = ttk.Label(head, text="–", style="T.TLabel")
        self.title.pack(side="left")
        self.btn_toggle = ttk.Button(head, text="Verbinden", command=self.toggle, width=26)
        self.btn_toggle.pack(side="right")
        info = ttk.Frame(right)
        info.pack(fill="x", pady=(8, 4))
        self.vals = {}
        fields = [("state", "Zustand"), ("origin", "Herkunft"), ("endpoint", "Endpunkt"), ("handshake", "Letzter Handshake"),
                  ("rx", "Empfangen"), ("tx", "Gesendet"), ("address", "Adresse"), ("dns", "DNS"), ("allowed", "Erlaubte Netze"),
                  ("pub", "Öffentlicher Schlüssel"), ("home", "Heimnetz-Erkennung")]
        for i, (k, t) in enumerate(fields):
            ttk.Label(info, text=t, style="K.TLabel").grid(row=i // 2, column=(i % 2) * 2, sticky="w", padx=(0, 8), pady=2)
            v = ttk.Label(info, text="–", wraplength=self.px(300))
            v.grid(row=i // 2, column=(i % 2) * 2 + 1, sticky="w", padx=(0, 24), pady=2)
            self.vals[k] = v
        info.columnconfigure(1, weight=1)
        info.columnconfigure(3, weight=1)
        self.canvas = tk.Canvas(right, height=self.px(200), background="#ffffff", highlightthickness=1, highlightbackground="#d0d4da")
        self.canvas.pack(fill="both", expand=True, pady=(6, 0))
        self.canvas.bind("<Configure>", lambda e: self.draw())

        bot = ttk.LabelFrame(r, text="Sicherung in VERA", padding=(10, 6))
        bot.pack(fill="x", padx=12, pady=(0, 6))
        self.btn_bk = ttk.Button(bot, text="Jetzt sichern …", command=self.backup_create)
        self.btn_bk.pack(side="left")
        self.btn_bl = ttk.Button(bot, text="Versionen / wiederherstellen …", command=self.backup_list)
        self.btn_bl.pack(side="left", padx=6)
        ttk.Label(bot, text="eigene Tunnel + Einstellungen, mit Kennwort verschlüsselt (VERA kennt es nicht)",
                  style="K.TLabel").pack(side="left", padx=10)
        self.foot = ttk.Label(r, text="", style="K.TLabel", padding=(12, 0, 12, 8))
        self.foot.pack(fill="x")

    # ------------------------------------------------------------------ reading
    def _read(self, name: str) -> dict:
        try:
            with open(os.path.join(self.data, name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def tick(self):
        try:
            self._tick()
        except Exception as e:  # noqa: BLE001 – the window must keep running
            self.foot.config(text=f"Anzeige-Fehler: {e}")
        self.root.after(1000, self.tick)

    def _tick(self):
        if time.time() - self.last_touch > 3:                           # tells the service: window open → live data
            try:
                p = os.path.join(self.data, "ui", "live.flag")
                with open(p, "a"):
                    pass
                os.utime(p, None)
            except OSError:
                pass
            self.last_touch = time.time()
        self.status = self._read("status.json")
        live = self._read("live.json")
        if live.get("t") and live.get("t") != self.live.get("t"):
            for n, x in (live.get("tunnels") or {}).items():
                h = self.hist.setdefault(n, collections.deque(maxlen=HISTORY))
                p = self.prev.get(n)
                if x.get("running") and p and live["t"] > p[0]:
                    dt = live["t"] - p[0]
                    rx, tx = (x.get("rx", 0) - p[1]) / dt, (x.get("tx", 0) - p[2]) / dt
                    h.append((live["t"], max(rx, 0), max(tx, 0)))
                elif not x.get("running"):
                    h.append((live["t"], 0, 0))
                self.prev[n] = (live["t"], x.get("rx", 0), x.get("tx", 0)) if x.get("running") else None
            self.live = live
        st = self.status
        state = st.get("state", "dead")
        if not st or (time.time() - float(st.get("updated") or 0) > 300):
            state = "dead"
        self.svc.config(text=f"Dienst: {SERVICE_TEXT.get(state, state)}" + (f" – {st['message']}" if st.get("message") else ""))
        rows = st.get("tunnels") or []
        names = [t["name"] for t in rows]
        for iid in self.tree.get_children():
            if iid not in names:
                self.tree.delete(iid)
        for i, t in enumerate(rows):
            vals = ("VERA" if t["source"] == "vera" else "eigener", STATE_TEXT.get(t["state"], t["state"]) if t["on"] else "getrennt")
            text = ("★ " if t["default"] else "   ") + t["name"]
            tag = (t["state"] if t["on"] else "off",)
            if self.tree.exists(t["name"]):
                self.tree.item(t["name"], text=text, values=vals, tags=tag)
                self.tree.move(t["name"], "", i)
            else:
                self.tree.insert("", i, iid=t["name"], text=text, values=vals, tags=tag)
        if (self.sel not in names) and names:
            self.sel = next((t["name"] for t in rows if t["default"]), names[0])
            self.tree.selection_set(self.sel)
        if not names:
            self.sel = None
        self.details()
        self.draw()
        live_age = time.time() - float(self.live.get("t") or 0)
        self.foot.config(text=("Arbeite …  " if self.busy else "") + (
            "Live-Daten: jede Sekunde" if live_age < 5 else "Live-Daten fehlen – läuft der Dienst VeraConnect?" if state != "dead"
            else "Der Dienst VeraConnect läuft nicht."))

    def row(self) -> dict | None:
        return next((t for t in self.status.get("tunnels") or [] if t["name"] == self.sel), None)

    def _select(self):
        s = self.tree.selection()
        if s:
            self.sel = s[0]
            self.details()
            self.draw()

    def details(self):
        t = self.row()
        manage = [self.btn_edit, self.btn_ren, self.btn_del, self.btn_def, self.btn_home]
        if not t:
            self.title.config(text="Noch kein Tunnel – „Neu“, „Aus Datei“ oder „Aus QR-Bild“")
            for v in self.vals.values():
                v.config(text="–")
            self.btn_toggle.state(["disabled"])
            for b in manage:
                b.state(["disabled"])
            return
        lv = (self.live.get("tunnels") or {}).get(t["name"], {}) if time.time() - float(self.live.get("t") or 0) < 5 else {}
        h = self.hist.get(t["name"]) or []
        rate = h[-1] if h else (0, 0, 0)
        self.title.config(text=("★ " if t["default"] else "") + t["name"] + (" – Standard-Tunnel" if t["default"] else ""))
        self.vals["state"].config(text=STATE_TEXT.get(t["state"], t["state"]) if t["on"] else "getrennt",
                                  foreground=STATE_COLOR.get(t["state"] if t["on"] else "off"))
        self.vals["origin"].config(text="VERA (zentral verwaltet)" if t["source"] == "vera" else (t.get("origin") or "eigener Tunnel"))
        self.vals["endpoint"].config(text=lv.get("endpoint") or t.get("endpoint") or "–")
        self.vals["handshake"].config(text=ago(lv.get("last_handshake") or t.get("last_handshake")) if t["on"] else "–")
        self.vals["rx"].config(text=f"{size(lv.get('rx', 0))}  ·  {size(rate[1])}/s" if lv.get("running") else "–")
        self.vals["tx"].config(text=f"{size(lv.get('tx', 0))}  ·  {size(rate[2])}/s" if lv.get("running") else "–")
        self.vals["address"].config(text=t.get("address") or "–")
        self.vals["dns"].config(text=t.get("dns") or "–")
        self.vals["allowed"].config(text=(t.get("allowed_ips") or "–") + ("  (ganzer Verkehr)" if t.get("full_tunnel") else ""))
        self.vals["pub"].config(text=t.get("public_key") or "–")
        hc = t.get("home") or {}
        if not hc.get("enabled", True):
            htxt = "aus"
        elif not t.get("home_networks"):
            htxt = "keine Heimnetze (Tunnel leitet alles um – unter „Heimnetz …“ eintragen)"
        else:
            htxt = ", ".join(t["home_networks"]) + " · Prüfung: " + (hc.get("check") or "VERA")
        if t.get("state") == "home" and t.get("home_why"):
            htxt = "pausiert – " + t["home_why"] + "\n" + htxt
        self.vals["home"].config(text=htxt)
        allowed = self.status.get("allow_disconnect", True) or t["source"] != "vera"
        if t["on"]:
            self.btn_toggle.config(text="Trennen" if allowed else "Trennen (in VERA nicht erlaubt)")
            self.btn_toggle.state(["!disabled"] if allowed else ["disabled"])
        else:
            self.btn_toggle.config(text="Verbinden")
            self.btn_toggle.state(["!disabled"])
        own = t["source"] != "vera"
        for b, ok in ((self.btn_edit, own), (self.btn_ren, True), (self.btn_del, own), (self.btn_def, not t["default"]), (self.btn_home, True)):
            b.state(["!disabled"] if ok and not self.busy else ["disabled"])

    # ------------------------------------------------------------------ graph
    def draw(self):
        c = self.canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 50 or h < 50:
            return
        k = self.k
        ml, mr, mt, mb = int(82 * k), int(14 * k), int(28 * k), int(24 * k)
        pts = list(self.hist.get(self.sel) or []) if self.sel else []
        now = time.time()
        top = max([1024.0] + [max(p[1], p[2]) for p in pts])
        step = 1024.0
        while top / step > 4:
            step *= 2 if str(step)[0] != "2" else 2.5
        top = step * (int(top / step) + 1)
        for i in range(5):
            y = mt + (h - mt - mb) * i / 4
            c.create_line(ml, y, w - mr, y, fill="#e6e8ec")
            c.create_text(ml - 6, y, text=size(top * (4 - i) / 4) + "/s", anchor="e", fill="#5b6170", font=("Segoe UI", 8))
        for i, lab in enumerate(("−3 min", "−2 min", "−1 min", "jetzt")):
            x = ml + (w - ml - mr) * i / 3
            c.create_text(x, h - mb + int(12 * k), text=lab, fill="#5b6170", font=("Segoe UI", 8),
                          anchor="w" if i == 0 else "e" if i == 3 else "center")

        def xy(p, k):
            x = ml + (w - ml - mr) * (1 - (now - p[0]) / HISTORY)
            y = mt + (h - mt - mb) * (1 - p[k] / top)
            return x, y
        for k, col in ((1, RX_COLOR), (2, TX_COLOR)):
            seg = [v for p in pts if now - p[0] <= HISTORY for v in xy(p, k)]
            if len(seg) >= 4:
                c.create_line(*seg, fill=col, width=2, smooth=False)
        last = pts[-1] if pts else (0, 0, 0)
        a = c.create_text(ml, int(13 * k), anchor="w", fill=RX_COLOR, font=("Segoe UI", 9, "bold"), text=f"↓ Empfang {size(last[1])}/s")
        x2 = (c.bbox(a) or (0, 0, ml + 150, 0))[2] + int(24 * k)
        c.create_text(x2, int(13 * k), anchor="w", fill=TX_COLOR, font=("Segoe UI", 9, "bold"), text=f"↑ Senden {size(last[2])}/s")
        if not pts:
            c.create_text(w / 2, h / 2, text="Noch keine Live-Daten" if self.sel else "", fill="#8c919a")

    # ------------------------------------------------------------------ actions (user)
    def toggle(self):
        t = self.row()
        if not t:
            return
        name = ("disconnect@" if t["on"] else "connect@") + t["name"] + ".flag"
        try:
            os.makedirs(os.path.join(self.data, "ui"), exist_ok=True)
            open(os.path.join(self.data, "ui", name), "w").close()
            self.foot.config(text=f"{'Trenne' if t['on'] else 'Verbinde'} {t['name']} …")
        except OSError as e:
            messagebox.showerror(TITLE, f"Geht nicht: {e}", parent=self.root)

    # ------------------------------------------------------------------ actions (administrator)
    def command(self, req: dict, done, wait_text: str = "Arbeite …"):
        self.busy += 1
        self.foot.config(text=wait_text)
        self.root.config(cursor="watch")

        def work():
            try:
                r = self._send(req)
            except Exception as e:  # noqa: BLE001
                r = {"ok": False, "message": str(e)}
            self.root.after(0, lambda: self._done(r, done))
        threading.Thread(target=work, daemon=True).start()

    def _done(self, r: dict, done):
        self.busy -= 1
        if not self.busy:
            self.root.config(cursor="")
        if not r.get("ok"):
            messagebox.showerror(TITLE, r.get("message") or "Fehler", parent=self.root)
            return
        if done:
            done(r.get("data") or {})

    def _send(self, req: dict) -> dict:
        vc = _vc()
        vc.DATA = self.data
        try:
            return vc.send_command(dict(req))
        except PermissionError:
            pass
        fd, path = tempfile.mkstemp(prefix="vera-connect-", suffix=".json")       # %TEMP% of the user, only for seconds
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(req, f, ensure_ascii=False)
        exe, params = _exe_args(["admin-cmd", path, "--data", self.data])
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 0) <= 32:
            try:
                os.remove(path)
            except OSError:
                pass
            return {"ok": False, "message": "Abgebrochen – dafür werden Administratorrechte gebraucht."}
        end = time.time() + 240
        while time.time() < end:
            if os.path.exists(path + ".res"):
                time.sleep(0.1)
                with open(path + ".res", encoding="utf-8") as f:
                    r = json.load(f)
                os.remove(path + ".res")
                return r
            time.sleep(0.3)
        return {"ok": False, "message": "Keine Antwort (Administrator-Fenster abgelehnt oder Dienst läuft nicht)."}

    def reopen_admin(self):
        exe, params = _exe_args(["gui", "--data", self.data])
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32:
            self.root.after(300, self.root.destroy)

    # ----- tunnel dialogs
    def tunnel_dialog(self, title: str, name: str = "", text: str = "", origin: str = "von Hand", edit: bool = False):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        d.geometry(f"{self.px(760)}x{self.px(580)}")
        frm = ttk.Frame(d, padding=12)
        frm.pack(fill="both", expand=True)
        row = ttk.Frame(frm)
        row.pack(fill="x")
        ttk.Label(row, text="Name").pack(side="left")
        ev = tk.StringVar(value=name)
        ent = ttk.Entry(row, textvariable=ev, width=34)
        ent.pack(side="left", padx=8)
        if edit:
            ent.state(["disabled"])
        ttk.Label(row, text="Buchstaben, Ziffern, - _ . = +  (max. 32)", style="K.TLabel").pack(side="left")
        cv = tk.BooleanVar(value=not edit)
        bar = ttk.Frame(frm)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        info = ttk.Label(frm, text="", style="K.TLabel", wraplength=self.px(720))
        info.pack(side="bottom", fill="x")
        txt = tk.Text(frm, font=("Consolas", 10), wrap="none", undo=True, height=10)
        txt.pack(fill="both", expand=True, pady=8)
        txt.insert("1.0", text)

        def check(*_):
            try:
                s = wgconf.summary(txt.get("1.0", "end"))
                peer = s["peers"][0]
                info.config(text=f"✓ gültig · öffentlicher Schlüssel {s['public_key']} · Adresse {', '.join(s['address']) or '–'} · "
                                 f"Gegenstelle {peer['endpoint'] or '–'} · Netze {', '.join(peer['allowed_ips'])}"
                                 + (" · leitet den ganzen Verkehr um" if s["full_tunnel"] else ""), foreground="#1f7a4d")
                return True
            except wgconf.ConfError as e:
                info.config(text=f"✗ {e}", foreground="#b3261e")
                return False

        def newkey():
            priv, pub = wgconf.keypair()
            cur = txt.get("1.0", "end")
            if "[Interface]" not in cur:
                txt.delete("1.0", "end")
                txt.insert("1.0", wgconf.template(priv))
            else:
                import re
                if re.search(r"(?im)^\s*PrivateKey\s*=.*$", cur):
                    cur = re.sub(r"(?im)^(\s*PrivateKey\s*=).*$", lambda m: f"{m.group(1)} {priv}", cur, count=1)
                else:
                    cur = cur.replace("[Interface]", f"[Interface]\nPrivateKey = {priv}", 1)
                txt.delete("1.0", "end")
                txt.insert("1.0", cur.rstrip("\n") + "\n")
            check()
            messagebox.showinfo(TITLE, f"Neues Schlüsselpaar erzeugt.\n\nÖffentlicher Schlüssel (bei der Gegenstelle als Peer eintragen):\n{pub}",
                                parent=d)

        def ok():
            if not check():
                return
            n = ev.get().strip()
            if not wgconf.valid_name(n):
                messagebox.showerror(TITLE, "Name: 1–32 Zeichen, nur Buchstaben, Ziffern und - _ . = + (keine Leerzeichen)", parent=d)
                return
            req = ({"action": "edit", "name": n, "text": txt.get("1.0", "end")} if edit else
                   {"action": "create", "name": n, "text": txt.get("1.0", "end"), "origin": origin, "connect": cv.get()})
            d.destroy()
            self.command(req, lambda r: self._after_change(r.get("name"), "Gespeichert"))

        ttk.Button(bar, text="Neues Schlüsselpaar", command=newkey).pack(side="left")
        if not edit:
            ttk.Checkbutton(bar, text="gleich verbinden", variable=cv).pack(side="left", padx=12)
        ttk.Button(bar, text="Abbrechen", command=d.destroy).pack(side="right")
        ttk.Button(bar, text="Speichern", command=ok).pack(side="right", padx=6)
        txt.bind("<<Modified>>", lambda e: (check(), txt.edit_modified(False)))
        check()
        ent.focus_set()

    def _after_change(self, name, text):
        if name:
            self.sel = name
        self.foot.config(text=text)

    def new_tunnel(self):
        priv, _ = wgconf.keypair()
        self.tunnel_dialog("Neuer Tunnel", "", wgconf.template(priv), "von Hand")

    def import_file(self):
        p = filedialog.askopenfilename(parent=self.root, title="WireGuard-Konfiguration importieren",
                                       filetypes=[("WireGuard-Konfiguration", "*.conf"), ("Alle Dateien", "*.*")])
        if not p:
            return
        try:
            with open(p, encoding="utf-8-sig") as f:
                text = f.read(70_000)
        except (OSError, UnicodeDecodeError) as e:
            messagebox.showerror(TITLE, f"Datei nicht lesbar: {e}", parent=self.root)
            return
        self.tunnel_dialog("Tunnel aus Datei importieren", wgconf.safe_name(os.path.splitext(os.path.basename(p))[0]), text,
                           "Datei " + os.path.basename(p)[:30])

    def import_qr(self):
        p = filedialog.askopenfilename(parent=self.root, title="Bild mit QR-Code wählen (oder Pfad eingeben)",
                                       filetypes=[("Bilder", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff"), ("Alle Dateien", "*.*")])
        if not p:
            return
        self.busy += 1
        self.foot.config(text="Lese QR-Code …")
        self.root.config(cursor="watch")

        def work():
            try:
                import qrdecode
                res = ("ok", qrdecode.decode_file(p))
            except Exception as e:  # noqa: BLE001
                res = ("err", str(e))
            self.root.after(0, lambda: shown(res))

        def shown(res):
            self.busy -= 1
            self.root.config(cursor="")
            if res[0] == "err":
                messagebox.showerror(TITLE, f"Im Bild wurde kein lesbarer QR-Code gefunden:\n{res[1]}", parent=self.root)
                return
            self.tunnel_dialog("Tunnel aus QR-Code importieren", wgconf.safe_name(os.path.splitext(os.path.basename(p))[0]), res[1],
                               "QR-Code " + os.path.basename(p)[:30])
        threading.Thread(target=work, daemon=True).start()

    def edit_tunnel(self):
        t = self.row()
        if not t or t["source"] == "vera":
            return
        self.command({"action": "get", "name": t["name"]},
                     lambda r: self.tunnel_dialog(f"Tunnel {t['name']} bearbeiten", t["name"], r.get("text", ""), edit=True))

    def rename(self):
        t = self.row()
        if not t:
            return
        new = simpledialog.askstring(TITLE, f"Neuer Name für „{t['name']}“:", initialvalue=t["name"], parent=self.root)
        if not new or new.strip() == t["name"]:
            return
        self.command({"action": "rename", "name": t["name"], "new": new.strip()}, lambda r: self._after_change(r.get("name"), "Umbenannt"))

    def delete(self):
        t = self.row()
        if not t or t["source"] == "vera":
            return
        if messagebox.askyesno(TITLE, f"Tunnel „{t['name']}“ löschen?\nDie Konfiguration (mit privatem Schlüssel) ist danach weg – "
                                      "außer in einer Sicherung.", parent=self.root, icon="warning"):
            self.command({"action": "delete", "name": t["name"]}, lambda r: self._after_change(None, "Gelöscht"))

    def make_default(self):
        t = self.row()
        if t:
            self.command({"action": "default", "name": t["name"]}, lambda r: self._after_change(t["name"], "Standard-Tunnel gesetzt"))

    def home_dialog(self):
        t = self.row()
        if not t:
            return
        hc = t.get("home") or {}
        d = tk.Toplevel(self.root)
        d.title(f"Heimnetz-Erkennung – {t['name']}")
        d.transient(self.root)
        f = ttk.Frame(d, padding=14)
        f.pack(fill="both", expand=True)
        ev = tk.BooleanVar(value=hc.get("enabled", True))
        nv, cv = tk.StringVar(value=", ".join(hc.get("networks") or [])), tk.StringVar(value=hc.get("check") or "")
        ttk.Checkbutton(f, text="Tunnel automatisch pausieren, wenn der Rechner im Heimnetz ist", variable=ev).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(f, text="So wird erkannt: Ein aktiver Netzwerkadapter (nicht WireGuard) hat eine Adresse in einem der Heimnetze, "
                          "und die Prüfadresse antwortet direkt über diesen Adapter – bei VERA mit der bekannten Kennung. "
                          "Ein fremdes Netz mit gleichem Adressbereich (Hotel, Kunde) zählt daher nicht. "
                          "Wird das Netz verlassen, verbindet sich der Tunnel wieder.", wraplength=self.px(620), justify="left",
                  style="K.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 10))
        auto = ", ".join(t.get("home_networks") or []) if not hc.get("networks") else ""
        ttk.Label(f, text="Heimnetze").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=nv, width=44).grid(row=2, column=1, sticky="w", pady=4)
        ttk.Label(f, text=f"leer = aus AllowedIPs des Tunnels{(' (jetzt: ' + auto + ')') if auto else ''}; bei 0.0.0.0/0 hier eintragen, z. B. 192.168.99.0/24",
                  style="K.TLabel").grid(row=3, column=1, sticky="w")
        ttk.Label(f, text="Prüfadresse").grid(row=4, column=0, sticky="w", pady=(10, 4))
        ttk.Entry(f, textvariable=cv, width=44).grid(row=4, column=1, sticky="w", pady=(10, 4))
        ttk.Label(f, text="leer = VERA (empfohlen); sonst host:port, z. B. 192.168.99.1:443 – muss im Heimnetz liegen",
                  style="K.TLabel").grid(row=5, column=1, sticky="w")

        def ok():
            req = {"action": "home", "name": t["name"], "enabled": ev.get(), "networks": nv.get(), "check": cv.get()}
            d.destroy()
            self.command(req, lambda r: self._after_change(t["name"], "Heimnetz-Erkennung gespeichert"))
        bar = ttk.Frame(f)
        bar.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(bar, text="Speichern", command=ok).pack(side="left", padx=6)
        ttk.Button(bar, text="Abbrechen", command=d.destroy).pack(side="left")

    # ----- backup
    def backup_create(self):
        d = tk.Toplevel(self.root)
        d.title("Sicherung in VERA anlegen")
        d.transient(self.root)
        f = ttk.Frame(d, padding=14)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Gesichert werden die eigenen Tunnel (mit privaten Schlüsseln), der Standard-Tunnel und die Einstellungen.\n"
                          "Alles wird hier auf dem Rechner mit dem Kennwort verschlüsselt; VERA speichert nur den verschlüsselten Block.\n"
                          "Ohne das Kennwort lässt sich die Sicherung nicht wiederherstellen.", justify="left").grid(row=0, column=0, columnspan=2, sticky="w")
        vs = [tk.StringVar() for _ in range(3)]
        for i, (lab, show) in enumerate((("Kommentar", ""), ("Kennwort (mind. 8 Zeichen)", "•"), ("Kennwort wiederholen", "•"))):
            ttk.Label(f, text=lab).grid(row=i + 1, column=0, sticky="w", pady=4)
            ttk.Entry(f, textvariable=vs[i], show=show, width=40).grid(row=i + 1, column=1, sticky="w", pady=4)

        def ok():
            if len(vs[1].get()) < 8:
                messagebox.showerror(TITLE, "Das Kennwort braucht mindestens 8 Zeichen.", parent=d)
                return
            if vs[1].get() != vs[2].get():
                messagebox.showerror(TITLE, "Die Kennwörter stimmen nicht überein.", parent=d)
                return
            req = {"action": "backup_create", "comment": vs[0].get(), "passphrase": vs[1].get()}
            d.destroy()
            self.command(req, lambda r: messagebox.showinfo(TITLE, "Sicherung in VERA gespeichert.", parent=self.root),
                         "Sichere zu VERA …")
        bar = ttk.Frame(f)
        bar.grid(row=5, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(bar, text="Sichern", command=ok).pack(side="left", padx=6)
        ttk.Button(bar, text="Abbrechen", command=d.destroy).pack(side="left")

    def backup_list(self):
        self.command({"action": "backup_list"}, self._backups_window, "Lade die Sicherungen aus VERA …")

    def _backups_window(self, data: dict):
        d = tk.Toplevel(self.root)
        d.title("Sicherungen in VERA")
        d.transient(self.root)
        d.geometry(f"{self.px(900)}x{self.px(400)}")
        f = ttk.Frame(d, padding=12)
        f.pack(fill="both", expand=True)
        cols = (("time", "Zeitpunkt", 130), ("host", "von Rechner", 120), ("tunnels", "Eigene Tunnel", 220), ("ver", "Version", 70),
                ("comment", "Kommentar", 200), ("size", "Größe", 60))
        sv = tk.BooleanVar(value=False)
        bar = ttk.Frame(f)
        bar.pack(side="bottom", fill="x", pady=(8, 0))
        tv = ttk.Treeview(f, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for k, t, w in cols:
            tv.heading(k, text=t)
            tv.column(k, width=self.px(w))
        tv.pack(fill="both", expand=True)
        items = data.get("backups") or []
        for b in items:
            m = b.get("meta") or {}
            tv.insert("", "end", iid=str(b["id"]), values=(b.get("created_local") or b.get("created", "")[:16].replace("T", " "),
                                                            m.get("hostname", ""), ", ".join(m.get("tunnels") or []) or "–",
                                                            m.get("client_version", ""), m.get("comment", ""), size(b.get("size", 0))))
        if not items:
            ttk.Label(f, text="Noch keine Sicherungen für diesen Rechner.", style="K.TLabel").pack(anchor="w", pady=6)

        def chosen():
            s = tv.selection()
            return int(s[0]) if s else None

        def restore():
            bid = chosen()
            if not bid:
                return
            pw = simpledialog.askstring(TITLE, "Kennwort der Sicherung:", show="•", parent=d)
            if not pw:
                return
            if not messagebox.askyesno(TITLE, "Wiederherstellen ersetzt alle eigenen Tunnel dieses Rechners durch die aus der Sicherung"
                                              + (" und übernimmt die Adressen von VERA/UMA" if sv.get() else "") + ". Weiter?",
                                       parent=d, icon="warning"):
                return
            d.destroy()
            self.command({"action": "backup_restore", "backup_id": bid, "passphrase": pw, "settings": sv.get()},
                         lambda r: messagebox.showinfo(TITLE, "Wiederhergestellt: " + (", ".join(r.get("tunnels") or []) or "keine eigenen Tunnel"),
                                                       parent=self.root), "Stelle wieder her …")

        def remove():
            bid = chosen()
            if bid and messagebox.askyesno(TITLE, "Diese Sicherung in VERA löschen?", parent=d, icon="warning"):
                d.destroy()
                self.command({"action": "backup_delete", "backup_id": bid}, lambda r: self.backup_list())
        ttk.Button(bar, text="Wiederherstellen …", command=restore).pack(side="left")
        ttk.Checkbutton(bar, text="auch Adressen von VERA und UMA übernehmen", variable=sv).pack(side="left", padx=10)
        ttk.Button(bar, text="Schließen", command=d.destroy).pack(side="right")
        ttk.Button(bar, text="Löschen", command=remove).pack(side="right", padx=6)


def _single_instance() -> bool:
    try:
        k = ctypes.windll.kernel32
        k.CreateMutexW(None, False, "Local\\VeraConnectWindow")
        if k.GetLastError() == 183:                                    # already open → bring to front
            u = ctypes.windll.user32
            h = u.FindWindowW(None, TITLE)
            if h:
                u.ShowWindow(h, 9)
                u.SetForegroundWindow(h)
            return False
    except (AttributeError, OSError):
        pass
    return True


def run(data: str, selftest: float = 0) -> int:
    if not selftest and not _single_instance():
        return 0
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)                  # sharp text instead of blurred scaling
    except (AttributeError, OSError):
        pass
    app = App(data)
    if selftest:
        app.root.after(int(selftest * 1000), app.root.destroy)
        app.root.mainloop()
        print("Fenster-Selbsttest: ok ·", len(app.status.get("tunnels") or []), "Tunnel")
        return 0
    app.root.mainloop()
    return 0
