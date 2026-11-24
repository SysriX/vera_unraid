"""VERA-Connect – tray icon for the logged-on user (Windows, standard library only: ctypes against user32/shell32).

Replaces the tray of WireGuard. The service runs in session 0 and writes <data>\\status.json; this program
(`vera-connect.exe tray`, started at every logon via HKLM\\...\\Run) shows it:

    icon     VERA shield with a status dot: green = connected · yellow = waiting for approval / connecting
             blue = disconnected by the user · red = no connection / blocked · grey = service not running
    menu     open the window (tunnels live, import, backup) · each tunnel on/off · connect default / disconnect all
             (the VERA tunnel only if VERA allows it) · fetch configuration again · status · check · log · settings (admin) · close
    double click opens the window
Commands go to the service as flag files in <data>\\ui (users may write there, nothing else).
(Window/menu code taken over from the DORA agent.)
"""
from __future__ import annotations

import ctypes
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes

CLASS = "VeraConnectTray"
WM_APP_TRAY = 0x8000 + 1
WM_TIMER, WM_COMMAND, WM_DESTROY, WM_CLOSE = 0x0113, 0x0111, 0x0002, 0x0010
WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_LBUTTONUP = 0x0203, 0x0205, 0x0202
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 1, 2, 4, 0x10
NIIF_INFO, NIIF_WARNING = 1, 2
MF_STRING, MF_GRAYED, MF_CHECKED, MF_POPUP, MF_SEPARATOR = 0, 1, 0x8, 0x10, 0x800
TPM_RETURNCMD, TPM_RIGHTBUTTON = 0x100, 0x2
IMAGE_ICON, LR_LOADFROMFILE = 1, 0x10
CMD_STATUS, CMD_REFRESH, CMD_LOG, CMD_SETTINGS, CMD_EXIT, CMD_CONNECT, CMD_DISCONNECT, CMD_DIAG, CMD_WINDOW = 1, 2, 3, 4, 5, 6, 7, 8, 9
CMD_TUNNEL = 100                                     # + index of the tunnel

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.CreateWindowExW.restype = wintypes.HWND
user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
user32.LoadImageW.restype = wintypes.HANDLE
user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
user32.CreatePopupMenu.restype = wintypes.HMENU
user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, wintypes.LPVOID]
user32.SetTimer.restype = ctypes.c_size_t
user32.FindWindowW.restype = wintypes.HWND
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
user32.RegisterWindowMessageW.restype = wintypes.UINT
kernel32.GetModuleHandleW.restype = wintypes.HMODULE


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON), ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD), ("szInfo", wintypes.WCHAR * 256),
                ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wintypes.HICON)]


class MSG(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("message", wintypes.UINT), ("wParam", wintypes.WPARAM), ("lParam", wintypes.LPARAM),
                ("time", wintypes.DWORD), ("pt", wintypes.POINT)]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]

COLORS = {"home": (46, 182, 125), "up": (46, 182, 125), "ready": (240, 180, 40), "down": (220, 70, 70), "pending": (240, 180, 40), "start": (240, 180, 40),
          "installing": (240, 180, 40), "user_off": (77, 195, 255), "offline": (220, 70, 70), "error": (220, 70, 70),
          "blocked": (220, 70, 70), "denied": (220, 70, 70), "no_url": (240, 180, 40), "dead": (130, 130, 130)}
STATE_TEXT = {"home": "im Heimnetz – Tunnel pausiert", "up": "verbunden", "ready": "verbindet …", "down": "keine Verbindung – wird neu verbunden", "pending": "wartet auf Freigabe in VERA",
              "start": "startet", "installing": "richtet WireGuard ein", "user_off": "getrennt (von Hand)", "offline": "VERA nicht erreichbar",
              "error": "Fehler", "blocked": "in VERA gesperrt", "denied": "von VERA abgelehnt", "no_url": "Adresse von VERA fehlt",
              "dead": "Dienst läuft nicht"}


TUNNEL_TEXT = {"home": "im Heimnetz (pausiert)", "up": "verbunden", "idle": "aktiv", "connecting": "verbindet …", "down": "keine Verbindung", "missing": "fehlt", "off": "getrennt"}


# ------------------------------------------------------------------ icons: the VERA shield (app/web/icon.svg) + status dot
# Drawn with simple geometry (no image library on the computers): viewBox 64×64, 4×4 supersampling per pixel.
BLUE, GREEN, ORANGE = (77, 195, 255), (61, 220, 132), (255, 179, 71)


def _seg(x, y, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    return ((x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2) ** 0.5


def _shield_half_width(y: float) -> float:
    """Half width of the shield at height y (top point 32,3 · shoulders at y=12 · straight to y=30 · tip at 32,61)."""
    if y < 3 or y > 61:
        return -1
    if y < 12:
        return 24 * (y - 3) / 9
    if y <= 30:
        return 24
    return 24 * (1 - ((y - 30) / 31) ** 1.7)


def _logo(x, y):
    """Colour (r, g, b, a) of the VERA shield at viewBox point (x, y)."""
    w_out, w_in = _shield_half_width(y), _shield_half_width(y)
    dx = abs(x - 32)
    if w_out < 0 or dx > w_out + 1.5:
        return (0, 0, 0, 0)
    if dx > w_in - 1.8 or y < 5 or y > 59:
        return (*BLUE, 255)                                                 # border
    g = max(0.0, min(1.0, (y - 3) / 58))
    c = (int(42 + (20 - 42) * g), int(46 + (22 - 46) * g), int(54 + (26 - 54) * g))
    if min(_seg(x, y, 19, 22, 32, 44), _seg(x, y, 32, 44, 45, 22)) <= 2.6:
        c = BLUE                                                            # the V
    if ((x - 19) ** 2 + (y - 22) ** 2) ** 0.5 <= 3.4:
        c = GREEN
    if ((x - 45) ** 2 + (y - 22) ** 2) ** 0.5 <= 3.4:
        c = ORANGE
    return (*c, 255)


def _pixels(size: int, rgb: tuple, grey: bool) -> bytes:
    """BGRA, bottom-up rows. Status dot lower right with white ring."""
    n, sub = size, 4
    out = bytearray()
    for py in range(n - 1, -1, -1):
        for px_ in range(n):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(sub):
                for sx in range(sub):
                    x = (px_ + (sx + 0.5) / sub) * 64 / n
                    y = (py + (sy + 0.5) / sub) * 64 / n
                    r, g, b, a = _logo(x, y)
                    if grey and a:
                        r = g = b = int(0.3 * r + 0.59 * g + 0.11 * b)
                    dd = ((x - 48) ** 2 + (y - 48) ** 2) ** 0.5
                    if rgb is not None and dd <= 17:
                        r, g, b, a = ((255, 255, 255) if dd > 13 else rgb) + (255,)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            a = acc[3] / (sub * sub)
            out += bytes((int(acc[2] / acc[3]), int(acc[1] / acc[3]), int(acc[0] / acc[3]), int(a))) if a else b"\x00\x00\x00\x00"
    return bytes(out)


def _ico(sizes, rgb: tuple, grey: bool = False) -> bytes:
    imgs = []
    for n in sizes:
        px = _pixels(n, rgb, grey)
        mask = bytes(((n + 31) // 32) * 4 * n)
        bih = struct.pack("<IiiHHIIiiII", 40, n, n * 2, 1, 32, 0, len(px) + len(mask), 0, 0, 0, 0)
        imgs.append((n, bih + px + mask))
    head = struct.pack("<HHH", 0, 1, len(imgs))
    off, dirs, data = 6 + 16 * len(imgs), b"", b""
    for n, img in imgs:
        dirs += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(img), off + len(data))
        data += img
    return head + dirs + data


_ICONS: dict = {}


def icon(state: str):
    if state not in _ICONS:
        path = os.path.join(tempfile.gettempdir(), f"vera-connect-tray-{state}.ico")
        with open(path, "wb") as f:
            f.write(_ico((16, 24, 32), COLORS.get(state, COLORS["dead"]), grey=state == "dead"))
        _ICONS[state] = user32.LoadImageW(None, path, IMAGE_ICON, 0, 0, LR_LOADFROMFILE)
    return _ICONS[state]


# ------------------------------------------------------------------ status
def read_status(data: str) -> dict:
    try:
        with open(os.path.join(data, "status.json"), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        return {"state": "dead", "shown": "dead"}
    if time.time() - float(st.get("updated") or 0) > 300 and not _service_running():
        st["state"] = "dead"
    st["shown"] = st.get("state") if st.get("state") in COLORS else "start"
    return st


def _service_running() -> bool:
    try:
        r = subprocess.run(stdin=subprocess.DEVNULL, args=["sc.exe", "query", "VeraConnect"], capture_output=True, text=True,
                           creationflags=0x08000000, timeout=10)
        return "RUNNING" in r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ago(t) -> str:
    if not t:
        return "nie"
    d = int(time.time() - float(t))
    return "gerade eben" if d < 60 else f"vor {d // 60} min" if d < 3600 else f"vor {d // 3600} h"


def my_version() -> str:
    return str(getattr(sys.modules.get("__main__"), "VERSION", "") or "")


def version_line(st: dict) -> str:
    """"VERA-Connect 1.3.1" – plus the version of the service if it differs (e.g. right after an update)."""
    mine = my_version() or st.get("version") or "?"
    svc = st.get("version")
    return f"VERA-Connect {mine}" + (f" (Dienst {svc})" if svc and svc != mine else "")


def tip_text(st: dict) -> str:
    t = f"{version_line(st)} – {STATE_TEXT.get(st['shown'], st['shown'])}"
    if st.get("tunnel"):
        t += f"\nTunnel: {st['tunnel']}"
    return t[:127]


def details(st: dict) -> str:
    lines = [f"Zustand: {STATE_TEXT.get(st['shown'], st['shown'])}"]
    if st.get("message"):
        lines.append(st["message"])
    tl = st.get("tunnels") or []
    if tl:
        for t in tl:
            lines.append(f"Tunnel {'★ ' if t.get('default') else ''}{t['name']}: {TUNNEL_TEXT.get(t['state'], t['state']) if t['on'] else 'getrennt'}"
                         + (f" (Handshake {_ago(t.get('last_handshake'))})" if t["on"] and t.get("last_handshake") else ""))
    else:
        lines.append(f"Tunnel: {st.get('tunnel') or '–'}")
    lines += [f"Letzter Handshake: {_ago(st.get('last_handshake'))}",
              f"VERA: {st.get('vera') or '–'} (zuletzt erreicht {_ago(st.get('server_ok'))})"]
    if st.get("update_state"):
        lines.append(f"Updates: {st['update_state']}")
    if st.get("last_error"):
        lines.append(f"Letzter Fehler: {st['last_error']}")
    lines += ["", version_line(st) + (f" · WireGuard {st['wg_version']}" if st.get("wg_version") else "")]
    return "\n".join(lines)


# ------------------------------------------------------------------ the tray window
class Tray:
    def __init__(self, data: str):
        self.data, self.st = data, {"shown": None}
        self.started, self.restarting = time.time(), False
        self.taskbar_created = -1
        hinst = kernel32.GetModuleHandleW(None)
        self._proc = WNDPROC(self._wndproc)
        wc = WNDCLASSW(lpfnWndProc=self._proc, hInstance=hinst, lpszClassName=CLASS)
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(0, CLASS, "VERA-Connect Tray", 0, 0, 0, 0, 0, None, None, hinst, None)
        self.taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self.nid = NOTIFYICONDATAW()
        self.nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        self.nid.hWnd, self.nid.uID, self.nid.uCallbackMessage = self.hwnd, 1, WM_APP_TRAY
        self._add()
        user32.SetTimer(self.hwnd, 1, 3000, None)
        self.refresh()

    def _add(self):
        self.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        self.nid.hIcon = icon("dead")
        self.nid.szTip = "VERA-Connect"
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self.nid))

    def balloon(self, title: str, text: str, kind: int = NIIF_INFO):
        self.nid.uFlags = NIF_INFO
        self.nid.szInfoTitle, self.nid.szInfo, self.nid.dwInfoFlags = title[:63], text[:255], kind
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))

    def restart_if_updated(self, st: dict) -> None:
        """After a self-update the service reports a new version and the EXE on disk is newer than this process:
        start the new tray and close this one (once)."""
        mine = getattr(sys.modules.get("__main__"), "VERSION", None)
        compiled = "__compiled__" in vars(sys.modules["__main__"]) or getattr(sys, "frozen", False)
        if self.restarting or not compiled or not mine or not st.get("version") or st["version"] == mine:
            return
        exe = os.path.abspath(sys.argv[0])
        try:
            if os.path.getmtime(exe) <= self.started:
                return
        except OSError:
            return
        self.restarting = True
        subprocess.Popen(f'cmd.exe /c ping -n 4 127.0.0.1 >nul & start "" "{exe}" tray', stdin=subprocess.DEVNULL, close_fds=True,
                         creationflags=0x00000008 | 0x08000000)
        user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)

    def refresh(self):
        st = read_status(self.data)
        self.restart_if_updated(st)
        self.nid.uFlags = NIF_ICON | NIF_TIP
        self.nid.hIcon = icon(st["shown"])
        self.nid.szTip = tip_text(st)
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))
        old = self.st.get("shown")
        if old not in (None, "dead") and old != st["shown"]:
            if st["shown"] == "up":
                self.balloon("VPN verbunden", f"Tunnel {st.get('tunnel') or ''}".strip())
            elif st["shown"] == "down" and old == "up":
                self.balloon("VPN getrennt", "VERA-Connect verbindet neu …", NIIF_WARNING)
            elif st["shown"] == "pending":
                self.balloon("VERA-Connect", "Der Rechner wartet in VERA auf Freigabe.")
        self.st = st

    def menu(self):
        st = self.st
        m = user32.CreatePopupMenu()
        user32.AppendMenuW(m, MF_STRING | MF_GRAYED, 0, version_line(st)[:100])
        user32.AppendMenuW(m, MF_STRING | MF_GRAYED, 0, STATE_TEXT.get(st["shown"], st["shown"])[:100]
                           + (f" · Tunnel {st['tunnel']}" if st.get("tunnel") else ""))
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        alive = st["shown"] != "dead"
        user32.AppendMenuW(m, MF_STRING, CMD_WINDOW, "VERA-Connect öffnen …")
        tl = st.get("tunnels") or []
        self.menu_tunnels = [t["name"] for t in tl]
        if len(tl) > 1:
            sub = user32.CreatePopupMenu()
            for i, t in enumerate(tl):
                locked = t["on"] and t["source"] == "vera" and not st.get("allow_disconnect", True)
                user32.AppendMenuW(sub, MF_STRING | (MF_CHECKED if t["on"] else 0) | (MF_GRAYED if locked or not alive else 0), CMD_TUNNEL + i,
                                   ("★ " if t.get("default") else "") + t["name"] + (" (VERA)" if t["source"] == "vera" else ""))
            user32.AppendMenuW(m, MF_POPUP | (0 if alive else MF_GRAYED), sub, "Tunnel")
        has_tunnel = bool(st.get("tunnel") or tl) and alive
        if st["shown"] == "user_off":
            user32.AppendMenuW(m, MF_STRING | (0 if has_tunnel else MF_GRAYED), CMD_CONNECT, "Verbinden (Standard-Tunnel)" if len(tl) > 1 else "Verbinden")
        else:
            allowed = st.get("allow_disconnect", True) or not any(t["source"] == "vera" for t in tl)
            user32.AppendMenuW(m, MF_STRING | (0 if has_tunnel else MF_GRAYED), CMD_DISCONNECT,
                               ("Alle trennen" if len(tl) > 1 else "Trennen") if allowed or len(tl) > 1 else "Trennen (in VERA nicht erlaubt)")
        user32.AppendMenuW(m, MF_STRING | (0 if st["shown"] != "dead" else MF_GRAYED), CMD_REFRESH, "Konfiguration neu von VERA holen")
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(m, MF_STRING, CMD_STATUS, "Status anzeigen …")
        user32.AppendMenuW(m, MF_STRING, CMD_DIAG, "Verbindung prüfen (Bericht auf den Desktop) …")
        user32.AppendMenuW(m, MF_STRING, CMD_LOG, "Protokoll öffnen")
        user32.AppendMenuW(m, MF_STRING, CMD_SETTINGS, "Einstellungen … (Administrator)")
        user32.AppendMenuW(m, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(m, MF_STRING, CMD_EXIT, "Tray-Symbol schließen (VPN bleibt bestehen)")
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)
        cmd = user32.TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(m)
        self.command(cmd)

    def flag(self, name: str, text: str):
        try:
            os.makedirs(os.path.join(self.data, "ui"), exist_ok=True)
            open(os.path.join(self.data, "ui", name), "w").close()
            self.balloon("VERA-Connect", text)
        except OSError as e:
            user32.MessageBoxW(None, f"Geht nicht: {e}", "VERA-Connect", 0x30)

    def command(self, cmd: int):
        if cmd >= CMD_TUNNEL:
            names = getattr(self, "menu_tunnels", [])
            if cmd - CMD_TUNNEL < len(names):
                n = names[cmd - CMD_TUNNEL]
                t = next((x for x in self.st.get("tunnels") or [] if x["name"] == n), None)
                if t:
                    self.flag(("disconnect@" if t["on"] else "connect@") + n + ".flag", f"{'Trenne' if t['on'] else 'Verbinde'} {n} …")
            return
        if cmd == CMD_WINDOW:
            self.open_window()
        elif cmd == CMD_STATUS:
            user32.MessageBoxW(None, details(read_status(self.data)) + "\n\n(Strg+C kopiert diese Meldung)", "VERA-Connect", 0x40)
        elif cmd == CMD_CONNECT:
            self.flag("connect.flag", "Verbindet …")
        elif cmd == CMD_DISCONNECT:
            self.flag("disconnect.flag", "Wird getrennt – bis „Verbinden“ oder zum nächsten Neustart.")
        elif cmd == CMD_REFRESH:
            self.flag("refresh.flag", "Holt die Konfiguration neu von VERA.")
        elif cmd == CMD_LOG:
            self.open_log()
        elif cmd == CMD_DIAG:
            self.diagnose()
        elif cmd == CMD_SETTINGS:
            compiled = "__compiled__" in vars(sys.modules["__main__"]) or getattr(sys, "frozen", False)
            exe = os.path.abspath(sys.argv[0]) if compiled else sys.executable
            args = "configure" if compiled else f'"{os.path.join(os.path.dirname(os.path.abspath(__file__)), "vera_connect.py")}" configure'
            shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        elif cmd == CMD_EXIT:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)

    def open_window(self):
        compiled = "__compiled__" in vars(sys.modules["__main__"]) or getattr(sys, "frozen", False)
        args = [os.path.abspath(sys.argv[0]), "gui", "--data", self.data] if compiled else             [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vera_connect.py"), "gui", "--data", self.data]
        try:
            subprocess.Popen(args, stdin=subprocess.DEVNULL, close_fds=True, creationflags=0x00000008 | 0x00000200 | 0x08000000)
        except OSError as e:
            user32.MessageBoxW(None, f"Fenster lässt sich nicht öffnen: {e}", "VERA-Connect", 0x30)

    def open_text(self, text: str, name: str, desktop: bool = False) -> str:
        """Write text to a file the user owns (Desktop or %TEMP%) and open it with the default editor."""
        base = os.path.join(os.path.expanduser("~"), "Desktop") if desktop else tempfile.gettempdir()
        if desktop and not os.path.isdir(base):
            base = tempfile.gettempdir()
        path = os.path.join(base, name)
        with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:
            f.write(text)
        os.startfile(path)                                     # noqa: S606 – default editor of the user
        return path

    def open_log(self):
        try:
            with open(os.path.join(self.data, "connect.log"), encoding="utf-8", errors="replace") as f:
                text = f.read()[-200_000:]
            self.open_text(text, "VERA-Connect-Protokoll.txt")
        except OSError as e:
            user32.MessageBoxW(None, f"Das Protokoll lässt sich nicht öffnen:\n{e}\n\nDatei: {os.path.join(self.data, 'connect.log')}",
                               "VERA-Connect", 0x30)

    def diagnose(self):
        """Connection check in the background, report on the desktop + clipboard."""
        self.balloon("VERA-Connect", "Prüfe die Verbindung zu VERA … (bis zu einer Minute)")

        def work():
            try:
                main = sys.modules["__main__"]
                fn = getattr(main, "diagnose", None)
                if fn is None:
                    import vera_connect
                    fn = vera_connect.diagnose
                text = fn(self.data)
            except Exception as e:  # noqa: BLE001
                text = f"Diagnose fehlgeschlagen: {e!r}"
            try:
                subprocess.run(["clip.exe"], input=text.encode("utf-16-le"), creationflags=0x08000000, timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                path = self.open_text(text, f"VERA-Connect-Diagnose-{time.strftime('%Y%m%d-%H%M')}.txt", desktop=True)
                self.balloon("VERA-Connect", f"Bericht gespeichert und in die Zwischenablage kopiert:\n{os.path.basename(path)}")
            except OSError as e:
                user32.MessageBoxW(None, text[:3000] + f"\n\n(Datei ging nicht: {e})", "VERA-Connect – Diagnose", 0x40)

        import threading
        threading.Thread(target=work, daemon=True).start()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_APP_TRAY:
            ev = lparam & 0xFFFF
            if ev == WM_RBUTTONUP:
                self.menu()
            elif ev == WM_LBUTTONDBLCLK:
                self.command(CMD_WINDOW)
            return 0
        if msg == WM_TIMER:
            self.refresh()
            return 0
        if msg == self.taskbar_created:                    # Explorer restarted
            self._add()
            self.refresh()
            return 0
        if msg in (WM_CLOSE, WM_DESTROY):
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def loop(self):
        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))


def close_running() -> bool:
    h = user32.FindWindowW(CLASS, None)
    if h:
        user32.PostMessageW(h, WM_CLOSE, 0, 0)
    return bool(h)


def run(data: str, selftest: float = 0) -> int:
    if user32.FindWindowW(CLASS, None):                    # one tray per session
        return 0
    t = Tray(data)
    if selftest:
        t.balloon("VERA-Connect", "Selbsttest")
        end = time.time() + selftest
        msg = MSG()
        while time.time() < end:
            while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.1)
        ok = bool(user32.FindWindowW(CLASS, None)) and bool(t.nid.hIcon)
        user32.PostMessageW(t.hwnd, WM_CLOSE, 0, 0)
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
            user32.DispatchMessageW(ctypes.byref(msg))
        print("Tray-Selbsttest:", "ok" if ok else "FEHLER", "·", tip_text(read_status(data)).replace("\n", " · "))
        return 0 if ok else 1
    t.loop()
    return 0
