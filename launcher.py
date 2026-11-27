"""Startpunkt der eigenständigen 4CPA-TraceMap-App (PyInstaller)."""
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

PORT = 8765
URL = f"http://127.0.0.1:{PORT}"


def running() -> bool:
    try:
        with urllib.request.urlopen(URL + "/api/settings", timeout=1.5) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    if running():  # läuft schon: nur Browser öffnen
        (webbrowser.open(URL) if not os.environ.get("TRACEMAP_NO_BROWSER") else None)
        return
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", PORT)) == 0:
            webbrowser.open(URL)  # Port belegt (anderer Prozess) – trotzdem öffnen
            return
    import uvicorn
    import app as tm

    def open_when_ready():
        for _ in range(40):
            if running():
                if not os.environ.get("TRACEMAP_NO_BROWSER"):
                    webbrowser.open(URL)
                return
            time.sleep(0.25)

    threading.Thread(target=open_when_ready, daemon=True).start()
    log = open(tm.DATA_DIR / "server.log", "a") if getattr(sys, "frozen", False) else sys.stderr
    sys.stdout = sys.stderr = log
    uvicorn.run(tm.app, host="127.0.0.1", port=PORT, log_config=None)


if __name__ == "__main__":
    main()
