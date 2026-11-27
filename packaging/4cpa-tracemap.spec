# PyInstaller-Spezifikation für Windows, Linux und macOS (gleiche Datei, Aufruf: pyinstaller packaging/4cpa-tracemap.spec)
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
ICONS = os.path.join(ROOT, "packaging", "icons")
NAME = "4CPA TraceMap"
icon = {"win32": "app.ico", "darwin": "app.icns"}.get(sys.platform, "app.png")
icon_path = os.path.join(ICONS, icon)
if not os.path.exists(icon_path):
    icon_path = None

hidden = (collect_submodules("uvicorn") + collect_submodules("dns")
          + ["spf", "dkim", "maxminddb", "app", "enrich", "geo", "intel", "report", "tracer"])

a = Analysis(
    [os.path.join(ROOT, "launcher.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "static"), "static"), (os.path.join(ROOT, "data", "countries.json"), "data")],
    hiddenimports=hidden,
    excludes=["tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name=NAME, console=False, icon=icon_path)
coll = COLLECT(exe, a.binaries, a.datas, name=NAME)
if sys.platform == "darwin":
    app = BUNDLE(coll, name=NAME + ".app", icon=icon_path, bundle_identifier="ch.transivroom.4cpa.tracemap")
