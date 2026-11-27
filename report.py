"""PDF-Report einer Auflösung (reportlab), mehrsprachig."""
import io
import json
import math
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.pdfgen.canvas import FILL_EVEN_ODD
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable, KeepTogether

BASE = Path(__file__).parent
I18N = json.loads((BASE / "static" / "i18n.json").read_text(encoding="utf-8"))
LOGO = BASE / "static" / "logo.png"
ACC = colors.HexColor("#2f7fd6")
DC = colors.HexColor("#9b4fd6")


def tr(lang: str, key: str, **kw) -> str:
    table = I18N.get(lang) or I18N["de"]
    return table.get(key, I18N["de"].get(key, key)).format(**kw)


def t(v) -> str:
    """Text für Helvetica (Latin-1) bereinigen und escapen."""
    s = "" if v is None else str(v)
    return escape(s.encode("latin-1", "replace").decode("latin-1"))


_COUNTRIES = None


def countries():
    global _COUNTRIES
    if _COUNTRIES is None:
        p = BASE / "data" / "countries.json"
        _COUNTRIES = json.loads(p.read_text()) if p.exists() else []
    return _COUNTRIES


class RouteMap(Flowable):
    """Karte mit Länderumrissen (Natural Earth), Gradnetz, Route und nummerierten Hops."""

    def __init__(self, hops, width, height, lang):
        super().__init__()
        self.hops, self.width, self.height, self.lang = hops, width, height, lang

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        cv, W, H = self.canv, self.width, self.height
        pts = [h for h in self.hops if h.get("lat") is not None]
        cv.saveState()
        cv.setFillColor(colors.HexColor("#dcebf7"))
        cv.setStrokeColor(colors.HexColor("#b4c4d6"))
        cv.rect(0, 0, W, H, fill=1, stroke=1)
        if not pts:
            cv.setFillColor(colors.HexColor("#555555"))
            cv.setFont("Helvetica", 10)
            cv.drawCentredString(W / 2, H / 2, tr(self.lang, "no_positions").encode("latin-1", "replace").decode("latin-1"))
            cv.restoreState()
            return
        lats = [p["lat"] for p in pts]
        lons = [p["lon"] for p in pts]
        lat_c, lon_c = (min(lats) + max(lats)) / 2, (min(lons) + max(lons)) / 2
        k = max(math.cos(math.radians(max(-80, min(80, lat_c)))), 0.2)  # Längenverzerrung
        span_lat = max((max(lats) - min(lats)) * 1.3, 6)
        span_lon = max((max(lons) - min(lons)) * 1.3, 10)
        scale = min(W / (span_lon * k), H / span_lat)  # Punkte pro Grad (Breite)
        half_lat, half_lon = H / scale / 2, W / scale / k / 2
        a, b = lat_c - half_lat, lat_c + half_lat
        c, e = lon_c - half_lon, lon_c + half_lon

        def xy(lat, lon):
            return (lon - c) * scale * k, (lat - a) * scale

        clip = cv.beginPath()
        clip.rect(0, 0, W, H)
        cv.clipPath(clip, stroke=0, fill=0)
        # Länder
        cv.setFillColor(colors.HexColor("#f6f4ee"))
        cv.setStrokeColor(colors.HexColor("#a9b4c2"))
        cv.setLineWidth(0.35)
        for poly in countries():
            x0, y0, x1, y1 = poly["bbox"]
            if x1 < c or x0 > e or y1 < a or y0 > b:
                continue
            path = cv.beginPath()
            for ring in poly["rings"]:
                for i, (lo, la) in enumerate(ring):
                    x, y = xy(la, lo)
                    (path.moveTo if i == 0 else path.lineTo)(x, y)
                path.close()
            cv.drawPath(path, stroke=1, fill=1, fillMode=FILL_EVEN_ODD)
        # Gradnetz
        step = 1 if (e - c) < 8 else 2 if (e - c) < 20 else 5 if (e - c) < 50 else 10 if (e - c) < 120 else 30
        cv.setStrokeColor(colors.HexColor("#8fa3b8"))
        cv.setFillColor(colors.HexColor("#5d6b7a"))
        cv.setLineWidth(0.25)
        cv.setFont("Helvetica", 5)
        g = math.ceil(c / step) * step
        while g <= e:
            x, _ = xy(a, g)
            cv.setDash(1, 2); cv.line(x, 0, x, H); cv.setDash()
            cv.drawString(x + 1.5, 2, f"{g}°")
            g += step
        g = math.ceil(a / step) * step
        while g <= b:
            _, y = xy(g, c)
            cv.setDash(1, 2); cv.line(0, y, W, y); cv.setDash()
            cv.drawString(2, y + 1.5, f"{g}°")
            g += step
        # Route (Großkreise)
        if len(pts) > 1:
            cv.setStrokeColor(ACC)
            cv.setLineWidth(1.1)
            cv.setDash(3, 2)
            for p, q in zip(pts, pts[1:]):
                path = cv.beginPath()
                for i, (la, lo) in enumerate(great_circle((p["lat"], p["lon"]), (q["lat"], q["lon"]))):
                    x, y = xy(la, lo)
                    (path.moveTo if i == 0 else path.lineTo)(x, y)
                cv.drawPath(path, stroke=1, fill=0)
            cv.setDash()
        cv.setFont("Helvetica-Bold", 6)
        for p in pts:
            x, y = xy(p["lat"], p["lon"])
            cv.setFillColor(DC if p.get("datacenter") else ACC)
            cv.setStrokeColor(colors.white)
            cv.setLineWidth(0.9)
            cv.circle(x, y, 5.2, stroke=1, fill=1)
            cv.setFillColor(colors.white)
            cv.drawCentredString(x, y - 2.1, str(p["hop"]))
        cv.restoreState()


def great_circle(a, b, n=32):
    """Punkte [(lat, lon)] auf dem Großkreis zwischen a und b (Längengrad entrollt)."""
    r = math.pi / 180
    la1, lo1, la2, lo2 = a[0] * r, a[1] * r, b[0] * r, b[1] * r
    d = 2 * math.asin(math.sqrt(math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2))
    if d < 1e-6:
        return [a, b]
    pts, prev = [], None
    for i in range(n + 1):
        f = i / n
        A, B = math.sin((1 - f) * d) / math.sin(d), math.sin(f * d) / math.sin(d)
        x = A * math.cos(la1) * math.cos(lo1) + B * math.cos(la2) * math.cos(lo2)
        y = A * math.cos(la1) * math.sin(lo1) + B * math.cos(la2) * math.sin(lo2)
        z = A * math.sin(la1) + B * math.sin(la2)
        lon = math.degrees(math.atan2(y, x))
        if prev is not None:
            while lon - prev > 180:
                lon -= 360
            while lon - prev < -180:
                lon += 360
        prev = lon
        pts.append((math.degrees(math.atan2(z, math.hypot(x, y))), lon))
    return pts


def route_map(hops, width, height, lang):
    return RouteMap(hops, width, height, lang)


def ms_cell(h, lang):
    if h.get("rtt_min") is None:
        return str(h.get("rtt_ms") or "")
    out = f"{h['rtt_avg']}<br/>({h['rtt_min']}-{h['rtt_max']})"
    if h.get("loss_pct"):
        out += f"<br/>{t(tr(lang, 'loss'))} {h['loss_pct']}%"
    return out


def build_pdf(r: dict, lang: str = "de") -> bytes:
    def T(k, **kw):
        return t(tr(lang, k, **kw))

    buf = io.BytesIO()

    def footer(canvas, doc):
        def l1(x):
            return x.encode("latin-1", "replace").decode("latin-1")
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.grey)
        canvas.drawString(15 * mm, 13 * mm, l1(f"Transivroom, Kasparstrasse 17, 3027 Bern, {tr(lang, 'country')}  -  www.transivroom.ch  -  admin@4cpa.ch"))
        canvas.drawString(15 * mm, 9 * mm, "4CPA TraceMap  -  " + l1(tr(lang, "footer")))
        canvas.drawRightString(195 * mm, 9 * mm, str(doc.page))
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=20 * mm, title=f"4CPA TraceMap {r['id']}",
                            author="Transivroom Division")
    ss = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=ss["BodyText"], fontSize=7.5, leading=9)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    title = ParagraphStyle("t", parent=ss["Title"], alignment=0, fontSize=18, leading=22)
    el = []
    head = Table([[Image(str(LOGO), 16 * mm, 16 * mm),
                   Paragraph(f"4CPA TraceMap<br/><font size=11>{T('report_title')}</font>", title)]],
                 colWidths=[20 * mm, 160 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    el.append(head)
    el.append(Spacer(1, 3 * mm))
    kind = T("type_mail") if r["kind"] == "mail" else T("type_web")
    el.append(Paragraph(f"<b>{T('type')}:</b> {kind} &nbsp; <b>{T('target_subject')}:</b> {t(r['query'])} &nbsp; "
                        f"<b>{T('created_utc')}:</b> {t(r['created'])} &nbsp; <b>ID:</b> {r['id']}", body))
    el.append(Spacer(1, 4 * mm))

    if r.get("sha256"):
        el.append(Paragraph(f"<b>{T('sha256')}:</b> <font name='Courier' size='6.5'>{r['sha256']}</font>", small))
        el.append(Spacer(1, 2 * mm))
    if r["kind"] == "mail":
        m = r["meta"]
        for lab, key in [("from", "from"), ("reply_to", "reply_to"), ("return_path", "return_path"),
                         ("message_id", "message_id"), ("x_orig", "x_originating_ip")]:
            if m.get(key):
                el.append(Paragraph(f"<b>{T(lab)}:</b> {t(m[key])}", body))
        el.append(Paragraph(f"<b>SPF:</b> {t(m.get('spf') or '-')} &nbsp; <b>DKIM:</b> {t(m.get('dkim') or '-')} "
                            f"&nbsp; <b>DMARC:</b> {t(m.get('dmarc') or '-')}", body))
        a = r.get("analysis") or {}
        if a.get("spf"):
            dk = a.get("dkim", {}).get("result", "-")
            dk = tr(lang, "dkim_not_verifiable") if dk == "not_verifiable" else dk
            el.append(Paragraph(f"<b>{T('spf_own')}:</b> {t(a['spf']['result'])} &nbsp; <b>{T('dkim_own')}:</b> {t(dk)}", body))
        if a.get("links"):
            ls = "; ".join(t(l["host"]) + (f" [{t(','.join(l['flags']))}]" if l["flags"] else "") for l in a["links"][:12])
            el.append(Paragraph(f"<b>{T('links')}:</b> {ls}", small))
    elif r.get("domain") and r["domain"].get("host"):
        o = r["domain"]
        rd, tl = o.get("rdap") or {}, o.get("tls") or {}
        ch = (o.get("http") or {}).get("chain", [])
        bits = []
        if rd.get("registered"):
            bits.append(f"<b>{T('registered')}:</b> {t(rd['registered'][:10])}" + (f" ({T('age_days', n=rd['age_days'])})" if rd.get("age_days") is not None else ""))
        if rd.get("registrar"):
            bits.append(f"<b>{T('registrar')}:</b> {t(rd['registrar'])}")
        if rd.get("nameservers"):
            bits.append(f"<b>{T('nameservers')}:</b> {t(', '.join(rd['nameservers']))}")
        if tl:
            bits.append(f"<b>{T('tls_cert')}:</b> " + t(tl.get("error") or f"{tl.get('issuer', '')}, {T('valid_until')} {(tl.get('not_after') or '')[:12]}"))
        if (o.get("http") or {}).get("cdn"):
            bits.append(f"<b>{T('cdn')}:</b> {t(o['http']['cdn'])}")
        if ch:
            bits.append(f"<b>{T('redirects')}:</b> " + t(" -> ".join(f"{c.get('status') or c.get('error')} {c['url']}" for c in ch)))
        el.append(Paragraph(f"<b>{T('sec_domain')}</b>", body))
        for b in bits:
            el.append(Paragraph(b, small))
    for w in r.get("warnings", []):
        txt = T(w["key"], **{k: v for k, v in w.items() if k != "key"}) if isinstance(w, dict) else t(w)
        el.append(Paragraph(f"<font color='#b36b00'><b>{T('warning')}:</b> {txt}</font>", body))
    el.append(Spacer(1, 3 * mm))

    el.append(route_map(r["hops"], 180 * mm, 85 * mm, lang))
    el.append(Paragraph(T("map_note"), small))
    el.append(Spacer(1, 4 * mm))

    cols = ["#", T("col_ip"), T("col_location"), T("col_asn"), T("col_dc"), T("abuse"), "ms (min-max)"]
    rows = [[Paragraph(f"<b>{x}</b>", small) for x in cols]]
    for h in r["hops"]:
        loc = ", ".join(x for x in [h.get("city"), h.get("country")] if x) or (tr(lang, "private_short") if h.get("private") else "-")
        f = h.get("facility")
        dc = (t(f"{f['name']} ({f['distance_km']} km)") if f else "") + (f"<br/>{T('hoster_dc')}" if h.get("datacenter") else "")
        label = tr(lang, h["label_key"]) if h.get("label_key") else h.get("label")
        ipcell = t(label or h.get("ip") or "* * *")
        hn = h.get("hostname") or h.get("hostname_header")
        if hn:
            ipcell += "<br/>" + t(hn)
        rep = h.get("reputation") or {}
        if rep.get("verdict") in ("bad", "suspicious"):
            why = rep.get("dnsbl", []) + ([tr(lang, "rep_tor")] if rep.get("tor") else []) + (["PBL"] if rep.get("pbl") else [])
            col = "#c0392b" if rep["verdict"] == "bad" else "#b36b00"
            ipcell += f"<br/><font color='{col}'>{t(tr(lang, 'rep_bad' if rep['verdict'] == 'bad' else 'rep_suspicious'))}: {t(', '.join(why))}</font>"
        if h.get("geo_suspect"):
            ipcell += f"<br/><font color='#b36b00'>{T('geo_suspect_tag')}</font>"
        if h.get("timestamp"):
            ipcell += "<br/>" + t(h["timestamp"])
        rows.append([Paragraph(str(h.get("hop", "")), small), Paragraph(ipcell, small),
                     Paragraph(t(loc), small), Paragraph(t(h.get("asn") or ""), small),
                     Paragraph(dc, small), Paragraph(t(h.get("abuse_contact") or ""), small),
                     Paragraph(ms_cell(h, lang), small)])
    tab = Table(rows, colWidths=[9 * mm, 37 * mm, 24 * mm, 26 * mm, 33 * mm, 29 * mm, 22 * mm], repeatRows=1)
    tab.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e3ebf5")),
                             ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c5d3e3")),
                             ("VALIGN", (0, 0), (-1, -1), "TOP"),
                             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")])]))
    el.append(tab)
    el.append(Spacer(1, 4 * mm))
    el.append(Paragraph(T("report_note"), small))
    if r.get("notes") or r.get("tags"):
        el.append(Spacer(1, 2 * mm))
        if r.get("tags"):
            el.append(Paragraph(f"<b>{T('tags').split(' (')[0]}:</b> {t(', '.join(r['tags']))}", small))
        if r.get("notes"):
            el.append(Paragraph(f"<b>{T('notes')}:</b> {t(r['notes']).replace(chr(10), '<br/>')}", small))
    el.append(Spacer(1, 3 * mm))
    imp = [Paragraph(f"<b>{T('imprint_title')}</b>", small), Spacer(1, 1 * mm),
           Paragraph(f"<b>{T('imprint_operator')}:</b> Transivroom Division &nbsp;-&nbsp; "
                     f"<b>{T('imprint_project')}:</b> 4CPA TraceMap", small),
           Paragraph(f"<b>{T('imprint_address')}:</b> Transivroom, Kasparstrasse 17, 3027 Bern, {T('country')}", small),
           Paragraph(f"<b>{T('imprint_web')}:</b> www.transivroom.ch &nbsp;-&nbsp; "
                     f"<b>{T('imprint_contact')}:</b> admin@4cpa.ch", small)]
    if (r.get("meta") or {}).get("local_only"):
        imp.append(Paragraph(t(tr(lang, "maxmind_notice")), small))
    el.append(KeepTogether(imp))
    doc.build(el, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
