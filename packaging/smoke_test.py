"""Startet die gebaute App, prüft Programmschnittstelle, Traceroute (127.0.0.1) und PDF, beendet sie wieder.

Aufruf: python packaging/smoke_test.py   (nach pyinstaller)
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "4CPA TraceMap"
BASE = "http://127.0.0.1:8765"
exe = {
    "win32": ROOT / "dist" / NAME / (NAME + ".exe"),
    "darwin": ROOT / "dist" / (NAME + ".app") / "Contents" / "MacOS" / NAME,
}.get(sys.platform, ROOT / "dist" / NAME / NAME)


def call(path, body=None, timeout=240):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json"} if body is not None else {},
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def main() -> int:
    if not exe.exists():
        print("FEHLER: nicht gefunden:", exe)
        return 1
    tmp = tempfile.mkdtemp(prefix="tracemap-smoke-")
    env = dict(os.environ, TRACEMAP_NO_BROWSER="1", TRACEMAP_DATA_DIR=tmp)  # eigener Datenordner, echte Daten bleiben unberührt
    proc = subprocess.Popen([str(exe)], env=env)
    try:
        for _ in range(120):
            try:
                st, body = call("/api/settings", timeout=2)
                break
            except Exception:
                time.sleep(0.5)
        else:
            print("FEHLER: App startet nicht")
            return 1
        settings = json.loads(body)
        assert settings["standalone"] is True, settings
        print("Start ok, Datenordner:", settings["local_db_path"])
        st, html = call("/")
        assert st == 200 and b"4CPA" in html
        st, body = call("/api/trace/web", {"target": "127.0.0.1", "lang": "de"})
        res = json.loads(body)
        assert st == 200 and len(res["hops"]) >= 1, res
        print("Traceroute ok:", [(h["hop"], h.get("ip")) for h in res["hops"]][:3])
        st, pdf = call(f"/api/results/{res['id']}/export?format=pdf&lang=de")
        assert st == 200 and pdf[:5] == b"%PDF-", pdf[:20]
        print("PDF ok:", len(pdf), "Bytes")
        call("/api/quit", {})
        proc.wait(timeout=20)
        print("Beendet ok")
        return 0
    except Exception as e:
        print("FEHLER:", type(e).__name__, e)
        return 1
    finally:
        if proc.poll() is None:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
