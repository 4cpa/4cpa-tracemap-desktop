import csv
import hashlib
import io
import json
import os
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import enrich
import geo
import intel
import report
import tracer

BASE = Path(__file__).parent
def user_data_dir() -> Path:
    if os.environ.get("TRACEMAP_DATA_DIR"):  # z. B. für Tests
        return Path(os.environ["TRACEMAP_DATA_DIR"])
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "4CPA TraceMap"
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "4CPA TraceMap"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "4CPA TraceMap"


if getattr(sys, "frozen", False):  # als eigenständige App: Daten im Benutzerordner
    DATA_DIR = user_data_dir()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    geo.DATA = DATA_DIR
    geo.CITY_DB = DATA_DIR / "GeoLite2-City.mmdb"
    geo.ASN_DB = DATA_DIR / "GeoLite2-ASN.mmdb"
else:
    DATA_DIR = BASE
DB = DATA_DIR / "results.db"
app = FastAPI(title="4CPA TraceMap")
I18N = json.loads((BASE / "static" / "i18n.json").read_text(encoding="utf-8"))
MAX_RAW = 100_000


def tr(lang: str, key: str, **kw) -> str:
    table = I18N.get(lang) or I18N["de"]
    return table.get(key, I18N["de"].get(key, key)).format(**kw)


# ------------------------------------------------------------------ Datenbank

def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, created TEXT, kind TEXT, query TEXT, data TEXT)")
    cols = {r[1] for r in c.execute("PRAGMA table_info(results)")}
    for col in ("sha256", "notes", "tags"):
        if col not in cols:
            c.execute(f"ALTER TABLE results ADD COLUMN {col} TEXT")
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
    return c


def get_settings() -> dict:
    with db() as c:
        s = dict(c.execute("SELECT key, value FROM settings").fetchall())
    return {"local_only": s.get("local_only") == "1", "abuseipdb_key": s.get("abuseipdb_key", "")}


def canon_hash(created: str, kind: str, query: str, data: dict) -> str:
    blob = json.dumps({"created": created, "kind": kind, "query": query, "data": data},
                      sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def save(kind: str, query: str, data: dict) -> dict:
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    digest = canon_hash(created, kind, query, data)
    with db() as c:
        cur = c.execute("INSERT INTO results (created, kind, query, data, sha256) VALUES (?,?,?,?,?)",
                        (created, kind, query, json.dumps(data), digest))
        rid = cur.lastrowid
    return {"id": rid, "created": created, "kind": kind, "query": query, "sha256": digest,
            "notes": "", "tags": [], **data}


def merge(entry: dict, info: dict) -> dict:
    entry.update({k: v for k, v in info.items() if k != "ip"})
    return entry


def add_reputation(infos: dict, key: str) -> None:
    public = [v for v in infos.values() if not v.get("private") and "ip" in v]
    with ThreadPoolExecutor(6) as ex:
        for v, rep in zip(public, ex.map(lambda v: intel.reputation(v["ip"], key), public)):
            v["reputation"] = rep


def geo_plausibility(hops: list, me: Optional[dict]) -> int:
    """Markiert Hops, deren Standort wegen der Antwortzeit physikalisch unmöglich ist."""
    if not me or me.get("lat") is None:
        return 0
    n = 0
    for h in hops:
        if h.get("lat") is None or not h.get("rtt_min") or h.get("hop") == 0:
            continue
        d = enrich._dist(me["lat"], me["lon"], h["lat"], h["lon"])
        min_rtt = d / 100.0  # Licht in Glasfaser ~200 km/ms, hin und zurück
        if h["rtt_min"] < min_rtt * 0.9 - 0.5:
            h["geo_suspect"] = True
            h["geo_min_rtt"] = round(min_rtt, 1)
            n += 1
    return n


# ------------------------------------------------------------------ Trace

class WebReq(BaseModel):
    target: str
    ip_version: str = "auto"
    lang: str = "de"


class MailReq(BaseModel):
    headers: str
    lang: str = "de"


def _check_local(settings: dict, lang: str):
    if settings["local_only"] and not geo.local_available():
        raise HTTPException(400, tr(lang, "err_no_local_db"))


@app.post("/api/trace/web")
def trace_web(req: WebReq):
    st = get_settings()
    _check_local(st, req.lang)
    local = st["local_only"]
    try:
        host = tracer.normalize_target(req.target)
        if req.ip_version not in ("auto", "4", "6"):
            raise tracer.TraceError("err_bad_version")
        hops = tracer.traceroute(host, mode=req.ip_version)
    except tracer.TraceError as e:
        raise HTTPException(400, tr(req.lang, e.key, **e.kw))
    except Exception as e:
        raise HTTPException(500, tr(req.lang, "err_trace_failed", msg=str(e)))
    me = "" if local else geo.my_public_ip()
    ips = [h["ip"] for h in hops if h["ip"]] + ([me] if me else [])
    ex = ThreadPoolExecutor(1)
    dom_future = None if local else ex.submit(intel.domain_info, host)
    infos = geo.lookup(ips, local)
    if not local:
        enrich.enrich(infos)
        add_reputation(infos, st["abuseipdb_key"])
    out = []
    if me:
        out.append(merge({"hop": 0, "ip": me, "label_key": "label_me_location", "rtt_ms": 0, "timeout": False}, infos.get(me, {})))
    for h in hops:
        out.append(merge(dict(h), infos.get(h["ip"], {})) if h["ip"] else h)
    suspects = geo_plausibility(out, infos.get(me) if me else None)
    domain = dom_future.result() if dom_future else {}
    ex.shutdown(wait=False)
    warnings = list(domain.pop("warnings", [])) if domain else []
    if suspects:
        warnings.append({"key": "warn_geo_suspect", "n": suspects})
    if any(h.get("reputation", {}).get("verdict") == "bad" for h in out):
        warnings.append({"key": "warn_rep_bad"})
    return save("web", host, {"hops": out, "meta": {"target": host, "ip_version": req.ip_version, "local_only": local},
                              "warnings": warnings, "domain": domain})


def header_block(raw: str) -> str:
    return raw.replace("\r\n", "\n").split("\n\n", 1)[0][:MAX_RAW]


@app.post("/api/trace/mail")
def trace_mail(req: MailReq):
    st = get_settings()
    _check_local(st, req.lang)
    local = st["local_only"]
    parsed = tracer.parse_headers(req.headers)
    analysis = intel.analyze_mail(req.headers, parsed["hops"])
    ips = []
    for h in parsed["hops"]:
        ips += h["ips"]
    if parsed["info"]["x_originating_ip"]:
        ips.append(parsed["info"]["x_originating_ip"])
    me = "" if local else geo.my_public_ip()
    if me:
        ips.append(me)
    infos = geo.lookup(ips, local)
    if not local:
        enrich.enrich(infos)
        add_reputation(infos, st["abuseipdb_key"])
    out = []
    n = 0
    for h in parsed["hops"]:
        n += 1
        ip = next((i for i in h["ips"] if geo.is_public(i)), h["ips"][0] if h["ips"] else None)
        e = {"hop": n, "ip": ip, "hostname_header": h["from_host"], "by": h["by_host"],
             "protocol": h["protocol"], "timestamp": h["timestamp"], "timeout": ip is None}
        if ip:
            merge(e, infos.get(ip, {}))
        out.append(e)
    if me:
        n += 1
        out.append(merge({"hop": n, "ip": me, "label_key": "label_me_recipient", "timeout": False}, infos.get(me, {})))
    warnings = parsed["warnings"] + analysis.pop("warnings")
    if any(h.get("reputation", {}).get("verdict") == "bad" for h in out):
        warnings.append({"key": "warn_rep_bad"})
    q = parsed["info"]["subject"] or parsed["info"]["from"] or "E-Mail"
    return save("mail", q, {"hops": out, "meta": {**parsed["info"], "local_only": local}, "warnings": warnings,
                            "analysis": analysis, "raw_headers": header_block(req.headers)})


# ------------------------------------------------------------------ Verlauf / Löschen / Notizen

@app.get("/api/results")
def list_results(q: str = ""):
    with db() as c:
        rows = c.execute("SELECT id, created, kind, query, tags, notes FROM results ORDER BY id DESC LIMIT 200").fetchall()
    out = []
    ql = q.strip().lower()
    for r in rows:
        tags = json.loads(r[4]) if r[4] else []
        if ql and ql not in (r[3] or "").lower() and ql not in (r[5] or "").lower() and not any(ql in t.lower() for t in tags):
            continue
        out.append({"id": r[0], "created": r[1], "kind": r[2], "query": r[3], "tags": tags, "has_notes": bool(r[5])})
    return out


def load(rid: int, lang: str = "de") -> dict:
    with db() as c:
        r = c.execute("SELECT id, created, kind, query, data, sha256, notes, tags FROM results WHERE id=?", (rid,)).fetchone()
    if not r:
        raise HTTPException(404, tr(lang, "err_not_found"))
    return {"id": r[0], "created": r[1], "kind": r[2], "query": r[3], "sha256": r[5],
            "notes": r[6] or "", "tags": json.loads(r[7]) if r[7] else [], **json.loads(r[4])}


@app.get("/api/results/{rid}")
def get_result(rid: int, lang: str = "de"):
    return load(rid, lang)


class PatchReq(BaseModel):
    notes: Optional[str] = None
    tags: Optional[List[str]] = None


@app.patch("/api/results/{rid}")
def patch_result(rid: int, req: PatchReq, lang: str = "de"):
    load(rid, lang)
    with db() as c:
        if req.notes is not None:
            c.execute("UPDATE results SET notes=? WHERE id=?", (req.notes[:20000], rid))
        if req.tags is not None:
            tags = [t.strip()[:30] for t in req.tags if t.strip()][:20]
            c.execute("UPDATE results SET tags=? WHERE id=?", (json.dumps(tags), rid))
    return {"ok": True}


@app.delete("/api/results/{rid}")
def delete_result(rid: int, lang: str = "de"):
    with db() as c:
        n = c.execute("DELETE FROM results WHERE id=?", (rid,)).rowcount
    if not n:
        raise HTTPException(404, tr(lang, "err_not_found"))
    return {"deleted": n}


@app.delete("/api/results")
def delete_all_results():
    with db() as c:
        n = c.execute("DELETE FROM results").rowcount
    return {"deleted": n}


@app.get("/api/results/{rid}/verify")
def verify(rid: int):
    r = load(rid)
    if not r["sha256"]:
        return {"status": "no_hash"}
    data = {k: v for k, v in r.items() if k not in ("id", "created", "kind", "query", "sha256", "notes", "tags")}
    ok = canon_hash(r["created"], r["kind"], r["query"], data) == r["sha256"]
    return {"status": "ok" if ok else "mismatch", "sha256": r["sha256"]}


# ------------------------------------------------------------------ Einstellungen

class SettingsReq(BaseModel):
    local_only: Optional[bool] = None
    abuseipdb_key: Optional[str] = None


@app.get("/api/settings")
def read_settings():
    s = get_settings()
    return {"local_only": s["local_only"], "has_abuseipdb_key": bool(s["abuseipdb_key"]),
            "local_db_available": geo.local_available(), "local_db_path": str(geo.CITY_DB),
            "standalone": bool(getattr(sys, "frozen", False))}


@app.put("/api/settings")
def write_settings(req: SettingsReq, lang: str = "de"):
    with db() as c:
        if req.local_only is not None:
            if req.local_only and not geo.local_available():
                raise HTTPException(400, tr(lang, "err_no_local_db"))
            c.execute("INSERT OR REPLACE INTO settings VALUES ('local_only', ?)", ("1" if req.local_only else "0",))
        if req.abuseipdb_key is not None:
            c.execute("INSERT OR REPLACE INTO settings VALUES ('abuseipdb_key', ?)", (req.abuseipdb_key.strip(),))
    return read_settings()


@app.post("/api/quit")
def quit_app():
    """Beendet die eigenständige App (nur im gebündelten Modus)."""
    if not getattr(sys, "frozen", False):
        raise HTTPException(400, "not standalone")
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return {"ok": True}


# ------------------------------------------------------------------ Meldungsentwurf

@app.get("/api/results/{rid}/report-draft")
def report_draft(rid: int):
    r = load(rid)
    hops = [h for h in r["hops"] if h.get("ip") and not h.get("label_key") and not h.get("private")]
    if not hops:
        raise HTTPException(400, "no hops")
    order = hops if r["kind"] == "mail" else list(reversed(hops))  # Mail: Ursprung zuerst; Web: Ziel zuerst
    targets, seen = [], set()
    for h in order:
        a = h.get("abuse_contact")
        if a and a.lower() not in seen:
            seen.add(a.lower())
            targets.append({"email": a, "ip": h["ip"], "asn": h.get("asn")})
    main = order[0]
    when = main.get("timestamp") or r["created"]
    asn = f" ({main['asn']})" if main.get("asn") else ""
    lines = ["Dear abuse team,\n"]
    if r["kind"] == "mail":
        subject = f"Abuse report: unsolicited email relayed via {main['ip']} ({when[:10]})"
        lines.append(f"I received an unsolicited email that, according to its headers, was handled by {main['ip']}{asn} on {when}.\n")
        lines.append("Relay chain (oldest first):")
        for h in r["hops"]:
            if h.get("label_key") or not h.get("ip"):
                continue
            rep = h.get("reputation") or {}
            tags = rep.get("dnsbl", []) + (["Tor exit"] if rep.get("tor") else [])
            flag = f"  [{', '.join(tags)}]" if tags else ""
            lines.append(f"  {h['hop']}. {h['ip']}  {h.get('hostname') or h.get('hostname_header') or ''}  {h.get('asn') or ''}  {h.get('timestamp') or ''}{flag}")
        m = r["meta"]
        a = r.get("analysis") or {}
        lines.append(f"\nAuthentication: SPF={(a.get('spf') or {}).get('result', m.get('spf') or 'n/a')}, "
                     f"DKIM={(a.get('dkim') or {}).get('result', m.get('dkim') or 'n/a')}, DMARC={m.get('dmarc') or 'n/a'}")
        lines.append(f"From: {m.get('from', '')}   Return-Path: {m.get('return_path', '')}")
    else:
        subject = f"Abuse report: {r['query']} ({main['ip']})"
        lines.append(f"I would like to report abusive content/activity associated with {r['query']}, hosted at {main['ip']}{asn}. "
                     f"Observed on {r['created']} (UTC).\n")
        lines.append("Network path (traceroute):")
        for h in r["hops"]:
            if h.get("ip") and not h.get("label_key"):
                lines.append(f"  {h['hop']}. {h['ip']}  {h.get('hostname') or ''}  {h.get('asn') or ''}")
    lines.append("\nPlease investigate and take appropriate action. Thank you.\n")
    if r["kind"] == "mail" and r.get("raw_headers"):
        lines.append("----- Original headers (recipient addresses removed) -----")
        lines.append(intel.redact_headers(r["raw_headers"]))
        lines.append("----- End of headers -----\n")
    lines.append(f"Generated with 4CPA TraceMap, record SHA-256: {r.get('sha256') or 'n/a'}")
    return {"to": targets, "subject": subject, "body": "\n".join(lines)}


# ------------------------------------------------------------------ Export

@app.get("/api/results/{rid}/export")
def export(rid: int, format: str = "json", lang: str = "de"):
    r = load(rid, lang)
    name = f"trace-{r['kind']}-{rid}"
    if format == "json":
        body, mime = json.dumps(r, indent=2, ensure_ascii=False), "application/json"
    elif format == "geojson":
        feats = []
        coords = []
        for h in r["hops"]:
            if h.get("lat") is not None:
                coords.append([h["lon"], h["lat"]])
                feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [h["lon"], h["lat"]]},
                              "properties": {k: v for k, v in h.items() if k not in ("lat", "lon")}})
        if len(coords) > 1:
            feats.append({"type": "Feature", "geometry": {"type": "LineString", "coordinates": coords},
                          "properties": {"name": "route"}})
        body, mime = json.dumps({"type": "FeatureCollection", "features": feats}, indent=2), "application/geo+json"
    elif format == "pdf":
        return Response(report.build_pdf(r, lang), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{name}.pdf"'})
    elif format == "csv":
        cols = ["hop", "ip", "hostname", "hostname_header", "city", "region", "country", "lat", "lon",
                "asn", "isp", "org", "datacenter", "facility_name", "facility_city", "abuse_contact", "reputation_verdict",
                "rtt_ms", "rtt_min", "rtt_max", "jitter_ms", "loss_pct", "geo_suspect", "timestamp", "protocol", "label"]
        buf = io.StringIO()
        w = csv.DictWriter(buf, cols, extrasaction="ignore")
        w.writeheader()
        rows = []
        for h in r["hops"]:
            f = h.get("facility") or {}
            lab = tr(lang, h["label_key"]) if h.get("label_key") else h.get("label")
            rows.append({**h, "label": lab, "facility_name": f.get("name"), "facility_city": f.get("city"),
                         "reputation_verdict": (h.get("reputation") or {}).get("verdict")})
        w.writerows(rows)
        body, mime = buf.getvalue(), "text/csv"
        format = "csv"
    else:
        raise HTTPException(400, tr(lang, "err_bad_format"))
    ext = "geojson" if format == "geojson" else format
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}.{ext}"'})


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
