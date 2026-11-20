"""Run VERA-Connect as a real Windows service – standard library only (ctypes against advapi32).
(Taken over from the DORA/ALMA agents.)

Installing registers the service "VeraConnect" (LocalSystem, automatic start, restart on failure).
The service starts the program with `run --service --data <data>`. Output goes to <data>/connect.log.
"""
from __future__ import annotations

import ctypes
import getpass
import os
import subprocess
import sys
import threading
from ctypes import wintypes

SERVICE_NAME = "VeraConnect"
DISPLAY_NAME = "VERA-Connect"
DESCRIPTION = "Hält die WireGuard-Verbindung zu VERA eingerichtet, verbunden und aktuell (VERA-Connect)."

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING = 1, 2, 3, 4
SERVICE_ACCEPT_STOP, SERVICE_ACCEPT_SHUTDOWN = 0x1, 0x4
SERVICE_CONTROL_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN = 1, 4, 5
NO_ERROR, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 0, 120, 1063


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD), ("dwControlsAccepted", wintypes.DWORD),
                ("dwWin32ExitCode", wintypes.DWORD), ("dwServiceSpecificExitCode", wintypes.DWORD),
                ("dwCheckPoint", wintypes.DWORD), ("dwWaitHint", wintypes.DWORD)]


HANDLER_EX = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)
SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


def run_as_service(run, stop_event: threading.Event) -> bool:
    """Hands control to the service control manager. run() is the blocking agent main loop; stop_event ends it.
    Returns False if the process was not started by the SCM (e.g. started from a console)."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER_EX, wintypes.LPVOID]
    advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
    advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    state = {"handle": None, "checkpoint": 0}
    status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 0, NO_ERROR, 0, 0, 10000)

    def report(current: int, wait_hint: int = 0, exit_code: int = NO_ERROR):
        status.dwCurrentState, status.dwWin32ExitCode, status.dwWaitHint = current, exit_code, wait_hint
        status.dwControlsAccepted = 0 if current == SERVICE_START_PENDING else SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        if current in (SERVICE_RUNNING, SERVICE_STOPPED):
            status.dwCheckPoint = 0
        else:
            state["checkpoint"] += 1
            status.dwCheckPoint = state["checkpoint"]
        advapi32.SetServiceStatus(state["handle"], ctypes.byref(status))

    def handler(control, event_type, event_data, context):
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            report(SERVICE_STOP_PENDING, 15000)
            stop_event.set()
            return NO_ERROR
        if control == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    handler_cb = HANDLER_EX(handler)

    def service_main(argc, argv):
        state["handle"] = advapi32.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler_cb, None)
        report(SERVICE_START_PENDING, 10000)
        report(SERVICE_RUNNING)
        code = NO_ERROR
        try:
            run()
        except BaseException:  # noqa: BLE001 – keep the SCM informed whatever happens
            import traceback
            traceback.print_exc()
            code = 1066          # ERROR_SERVICE_SPECIFIC_ERROR → triggers the configured restart
        report(SERVICE_STOPPED, exit_code=code)

    main_cb = SERVICE_MAIN(service_main)
    table = (SERVICE_TABLE_ENTRYW * 2)(SERVICE_TABLE_ENTRYW(SERVICE_NAME, main_cb), SERVICE_TABLE_ENTRYW(None, SERVICE_MAIN()))
    if not advapi32.StartServiceCtrlDispatcherW(table):
        if ctypes.get_last_error() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            return False
        raise ctypes.WinError(ctypes.get_last_error())
    return True


# ------------------------------------------------------------------ install / remove
def _sc(*args: str, check: bool = True) -> str:
    r = subprocess.run(stdin=subprocess.DEVNULL, args=["sc.exe", *args], capture_output=True, text=True, creationflags=0x08000000)
    out = (r.stdout + r.stderr).strip()
    if check and r.returncode != 0:
        raise RuntimeError(f"sc.exe {args[0]}: {out}")
    return out


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def own_command(data_dir: str) -> str:
    """Command line the service runs: the compiled vera-connect.exe, or python.exe + the script."""
    compiled = "__compiled__" in globals() or getattr(sys, "frozen", False) or "__compiled__" in vars(sys.modules["__main__"])
    exe = os.path.abspath(sys.argv[0]) if compiled else sys.executable
    parts = [exe] if compiled else [exe, os.path.abspath(sys.modules["__main__"].__file__)]
    parts += ["run", "--service", "--data", data_dir]
    return subprocess.list2cmdline(parts)


def install(data_dir: str, account: str = "", password: str | None = None) -> None:
    if not _is_admin():
        raise SystemExit("Bitte als Administrator ausführen (Eingabeaufforderung/PowerShell „Als Administrator“).")
    os.makedirs(data_dir, exist_ok=True)
    if _query_state() is not None:
        stop()
        _sc("delete", SERVICE_NAME, check=False)
    args = ["create", SERVICE_NAME, "binPath=", own_command(data_dir), "start=", "auto", "DisplayName=", DISPLAY_NAME]
    if account:
        if password is None:
            password = getpass.getpass(f"Passwort für {account}: ")
        args += ["obj=", account, "password=", password]
    _sc(*args)
    _sc("description", SERVICE_NAME, DESCRIPTION)
    _sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/300000")
    _sc("failureflag", SERVICE_NAME, "1", check=False)
    _sc("start", SERVICE_NAME)
    print(f"Dienst „{DISPLAY_NAME}“ installiert und gestartet. Protokoll: {os.path.join(data_dir, 'connect.log')}")


def _query_state() -> int | None:
    import re
    out = _sc("query", SERVICE_NAME, check=False)
    # "STATE : 4 RUNNING" / German "STATUS : 4 RUNNING" – the state words stay English
    m = re.search(r":\s*(\d)\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)", out)
    return int(m.group(1)) if m else None


def stop() -> None:
    import time
    if _query_state() not in (None, SERVICE_STOPPED):
        _sc("stop", SERVICE_NAME, check=False)
        for _ in range(30):
            if _query_state() in (None, SERVICE_STOPPED):
                break
            time.sleep(1)


def start() -> None:
    _sc("start", SERVICE_NAME, check=False)


def remove() -> None:
    if not _is_admin():
        raise SystemExit("Bitte als Administrator ausführen.")
    stop()
    _sc("delete", SERVICE_NAME)
    print("Dienst entfernt.")


def status() -> str:
    names = {None: "nicht installiert", 1: "gestoppt", 2: "startet", 3: "stoppt", 4: "läuft"}
    return names.get(_query_state(), "unbekannt")
