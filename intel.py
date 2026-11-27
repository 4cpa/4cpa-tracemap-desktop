"""Reputation, Mail-Analyse und Domain-/Web-Infos (alles passiv, nur Lesezugriffe)."""
import email
import email.policy
import ipaddress
import json
import re
import socket
import ssl
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlsplit, urljoin

import dns.exception
import dns.resolver
import dns.reversename

# ------------------------------------------------------------------ Reputation

DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "psbl.surriel.com", "dnsbl.dronebl.org", "all.s5h.net"]
TOR_URL = "https://check.torproject.org/torbulkexitlist"
_tor = {"t": 0.0, "set": set()}
_rep_cache: dict = {}


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 3.0
    r.timeout = 2.0
    return r


def tor_exits() -> set:
    if time.time() - _tor["t"] > 6 * 3600:
        try:
            req = urllib.request.Request(TOR_URL, headers={"User-Agent": "tracemap"})
            with urllib.request.urlopen(req, timeout=10) as r:
                _tor["set"] = {x.strip() for x in r.read().decode().splitlines() if x.strip()}
            _tor["t"] = time.time()
        except Exception:
            _tor["t"] = time.time() - 5 * 3600  # in 1 h erneut versuchen
    return _tor["set"]


def _dnsbl_name(ip: str, zone: str) -> str:
    rev = dns.reversename.from_address(ip).to_text().rstrip(".")
    for suf in (".in-addr.arpa", ".ip6.arpa"):
        if rev.endswith(suf):
            rev = rev[: -len(suf)]
    return f"{rev}.{zone}"


def _dnsbl_check(args):
    ip, zone = args
    try:
        ans = _resolver().resolve(_dnsbl_name(ip, zone), "A")
        codes = [a.to_text() for a in ans]
        # 127.255.255.x = Abfrage über offenen Resolver abgelehnt, kein Treffer
        if all(c.startswith("127.255.255.") for c in codes):
            return None
        if zone == "zen.spamhaus.org":
            last = {int(c.split(".")[-1]) for c in codes}
            if last <= {10, 11}:  # PBL = Richtlinienliste für Endkunden-Adressen, kein Spam-Nachweis
                return "pbl"
        return zone
    except Exception:
        return None


def _abuseipdb(ip: str, key: str):
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": key, "Accept": "application/json", "User-Agent": "tracemap"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.load(r)["data"]
        return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports")}
    except Exception:
        return None


def reputation(ip: str, abuseipdb_key: str = "") -> dict:
    ck = (ip, bool(abuseipdb_key))
    hit = _rep_cache.get(ck)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    tor = ip in tor_exits()
    with ThreadPoolExecutor(len(DNSBLS)) as ex:
        found = [z for z in ex.map(_dnsbl_check, [(ip, z) for z in DNSBLS]) if z]
    pbl = "pbl" in found
    lists = [z for z in found if z != "pbl"]
    ab = _abuseipdb(ip, abuseipdb_key) if abuseipdb_key else None
    score = (ab or {}).get("score")
    if lists or (score is not None and score >= 50):
        verdict = "bad"
    elif tor or pbl or (score is not None and score >= 10):
        verdict = "suspicious"
    else:
        verdict = "ok"
    res = {"verdict": verdict, "tor": tor, "dnsbl": lists, "pbl": pbl}
    if ab:
        res["abuseipdb"] = ab
    _rep_cache[ck] = (time.time(), res)
    return res


# ------------------------------------------------------------------ Mail-Analyse

BRANDS = ["paypal.com", "google.com", "apple.com", "amazon.com", "microsoft.com", "netflix.com", "facebook.com",
          "instagram.com", "dhl.com", "ups.com", "fedex.com", "post.ch", "postfinance.ch", "swisscom.ch",
          "ubs.com", "raiffeisen.ch", "zkb.ch", "sunrise.ch", "twint.ch", "visa.com", "mastercard.com",
          "paypal.ch", "ebay.com", "linkedin.com", "dropbox.com", "docusign.com", "gmail.com", "outlook.com"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
              "shorturl.at", "tiny.cc"}
HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "|": "l", "$": "s"})
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac"}


def reg_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(host: str):
    """Gibt die nachgeahmte Marke zurück oder None."""
    d = reg_domain(host)
    if d in BRANDS:
        return None
    label = d.split(".")[0]
    norm = label.translate(HOMOGLYPH).replace("-", "")
    for b in BRANDS:
        bl = b.split(".")[0]
        if len(bl) < 5:
            continue
        if norm == bl or _lev(norm, bl) == 1 or (bl in norm and d != b):
            return b
    if host.startswith("xn--") or ".xn--" in host:
        return "punycode"
    return None


def _domain_of(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9.-]+)", addr or "")
    return m.group(1).lower() if m else ""


def analyze_mail(raw: str, hops: list) -> dict:
    msg = email.message_from_string(raw, policy=email.policy.default)
    from_d = _domain_of(str(msg.get("From", "")))
    reply_d = _domain_of(str(msg.get("Reply-To", "")))
    ret_d = _domain_of(str(msg.get("Return-Path", "")))
    out = {"from_domain": from_d, "reply_to_domain": reply_d, "return_path_domain": ret_d, "warnings": []}
    W = out["warnings"]
    if reply_d and from_d and reg_domain(reply_d) != reg_domain(from_d):
        W.append({"key": "warn_replyto_mismatch", "a": from_d, "b": reply_d})
    if ret_d and from_d and reg_domain(ret_d) != reg_domain(from_d):
        W.append({"key": "warn_returnpath_mismatch", "a": from_d, "b": ret_d})
    brand = lookalike(from_d) if from_d else None
    if brand:
        W.append({"key": "warn_lookalike", "host": from_d, "brand": brand})

    # SPF: Verbindung zum eigenen Provider = zuletzt hinzugefügter Received-Header mit öffentlicher IP
    spf_res = {"result": "none"}
    try:
        import spf
        ext = [h for h in hops if h.get("ips") and any(ipaddress.ip_address(i).is_global for i in h["ips"])]
        if ext and ret_d:
            last = ext[-1]
            ip = next(i for i in last["ips"] if ipaddress.ip_address(i).is_global)
            mailfrom = re.search(r"<?([^<>\s]+@[^<>\s]+)>?", str(msg.get("Return-Path", ""))).group(1)
            helo = (last.get("from_host") or "").strip("[]") or "unknown"
            res, expl = spf.check2(i=ip, s=mailfrom, h=helo, timeout=6)[-2:]
            spf_res = {"result": res, "ip": ip, "explanation": expl}
    except Exception as e:
        spf_res = {"result": "error", "explanation": str(e)[:100]}
    out["spf"] = spf_res
    if spf_res["result"] in ("fail", "softfail", "permerror"):
        W.append({"key": "warn_spf_check", "val": spf_res["result"]})

    # DKIM: nur mit vollständiger Nachricht (Header + Body) prüfbar
    dk = {"result": "not_verifiable"}
    try:
        import dkim
        body = raw.replace("\r\n", "\n").split("\n\n", 1)
        has_body = len(body) > 1 and body[1].strip() != ""
        if msg.get("DKIM-Signature") and has_body:
            ok = dkim.verify(raw.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace"))
            dk = {"result": "pass" if ok else "fail"}
        elif not msg.get("DKIM-Signature"):
            dk = {"result": "none"}
    except Exception as e:
        dk = {"result": "error", "explanation": str(e)[:100]}
    out["dkim"] = dk
    if dk["result"] == "fail":
        W.append({"key": "warn_dkim_check", "val": "fail"})

    # Links im Text
    urls = []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                txt = part.get_content()
            except Exception:
                continue
            urls += re.findall(r"https?://[^\s\"'<>)\]]+", str(txt))
    links, seen = [], set()
    for u in urls:
        host = (urlsplit(u).hostname or "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        flags = []
        b = lookalike(host)
        if b:
            flags.append("lookalike:" + b)
            if host != from_d:  # Absenderdomain wurde oben schon gemeldet
                W.append({"key": "warn_lookalike", "host": host, "brand": b})
        if host in SHORTENERS:
            flags.append("shortener")
            W.append({"key": "warn_shortener", "host": host})
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append("ip_url")
        links.append({"url": u[:200], "host": host, "flags": flags})
        if len(links) >= 30:
            break
    out["links"] = links
    return out


def redact_headers(raw: str) -> str:
    """Entfernt Empfängeradressen aus Headern (To/Cc/Delivered-To/...)."""
    msg = email.message_from_string(raw, policy=email.policy.default)
    addrs = set()
    for h in ("To", "Cc", "Bcc", "Delivered-To", "X-Original-To", "Envelope-To"):
        for v in msg.get_all(h) or []:
            addrs.update(a.lower() for a in re.findall(r"[\w.+'-]+@[\w.-]+", str(v)))
    out = raw
    for a in addrs:
        out = re.sub(re.escape(a), "[redacted]", out, flags=re.I)
    return out


# ------------------------------------------------------------------ Domain / Web

_dns_boot: dict = {}


def _get_json(url, headers=None, timeout=8):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "tracemap"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def rdap_domain(host: str) -> dict:
    tld = host.rsplit(".", 1)[-1].lower()
    if "s" not in _dns_boot:
        _dns_boot["s"] = _get_json("https://data.iana.org/rdap/dns.json", timeout=10)["services"]
    base = next((urls[0] for tlds, urls in _dns_boot["s"] if tld in tlds), None)
    if not base:
        return {}
    d = _get_json(f"{base.rstrip('/')}/domain/{reg_domain(host)}", {"Accept": "application/rdap+json", "User-Agent": "tracemap"}, 10)
    info = {"status": d.get("status", [])[:5], "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])][:6]}
    for ev in d.get("events", []):
        a = ev.get("eventAction")
        if a == "registration":
            info["registered"] = ev.get("eventDate")
        elif a == "expiration":
            info["expires"] = ev.get("eventDate")
        elif a == "last changed":
            info["changed"] = ev.get("eventDate")
    for e in d.get("entities", []):
        if "registrar" in e.get("roles", []):
            for it in (e.get("vcardArray") or [None, []])[1]:
                if it[0] == "fn":
                    info["registrar"] = it[3]
    return info


def dns_records(host: str) -> dict:
    out = {}
    r = _resolver()
    for t in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            vals = [a.to_text().strip('"')[:150] for a in r.resolve(host, t)]
            out[t] = vals[:6]
        except Exception:
            pass
    return out


def tls_info(host: str) -> dict:
    ctx = ssl.create_default_context()
    info = {}
    try:
        with socket.create_connection((host, 443), timeout=6) as s:
            try:
                ss = ctx.wrap_socket(s, server_hostname=host)
            except ssl.SSLCertVerificationError as e:
                info["error"] = e.verify_message
                return info
            with ss:
                c = ss.getpeercert()
                info["issuer"] = " ".join(v for t in c.get("issuer", []) for k, v in t if k == "organizationName")
                info["subject"] = " ".join(v for t in c.get("subject", []) for k, v in t if k == "commonName")
                info["not_before"] = c.get("notBefore")
                info["not_after"] = c.get("notAfter")
                info["san"] = [v for k, v in c.get("subjectAltName", []) if k == "DNS"][:8]
                try:
                    exp = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    info["days_left"] = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    pass
    except Exception as e:
        info["error"] = str(e)[:100]
    return info


CDN_SIGNS = [("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-fastly-request-id", "Fastly"),
             ("x-azure-ref", "Azure Front Door"), ("x-vercel-id", "Vercel"), ("x-akamai-transformed", "Akamai"),
             ("x-sucuri-id", "Sucuri"), ("x-iinfo", "Imperva")]


def _is_public_host(host: str) -> bool:
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            if not ipaddress.ip_address(sa[0]).is_global:
                return False
        return True
    except Exception:
        return False


def http_chain(host: str, max_hops: int = 8) -> dict:
    url = f"https://{host}/"
    chain, cdn = [], None
    for _ in range(max_hops):
        u = urlsplit(url)
        if not u.hostname or not _is_public_host(u.hostname):
            chain.append({"url": url, "error": "blocked"})
            break
        try:
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                conn = HTTPSConnection(u.hostname, u.port or 443, timeout=8, context=ctx)
            else:
                conn = HTTPConnection(u.hostname, u.port or 80, timeout=8)
            conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""),
                         headers={"User-Agent": "Mozilla/5.0 (4CPA TraceMap)", "Accept": "*/*"})
            r = conn.getresponse()
            hdr = {k.lower(): v for k, v in r.getheaders()}
            entry = {"url": url, "status": r.status, "server": hdr.get("server", "")[:60]}
            conn.close()
        except Exception as e:
            chain.append({"url": url, "error": str(e)[:100]})
            break
        chain.append(entry)
        for k, name in CDN_SIGNS:
            if k in hdr:
                cdn = name
        if not cdn and "cloudflare" in hdr.get("server", "").lower():
            cdn = "Cloudflare"
        if not cdn and "cloudfront" in hdr.get("via", "").lower():
            cdn = "Amazon CloudFront"
        if r.status in (301, 302, 303, 307, 308) and hdr.get("location"):
            url = urljoin(url, hdr["location"])
            continue
        break
    return {"chain": chain, "cdn": cdn}


def domain_info(host: str) -> dict:
    """Domain-Registrierung, DNS, TLS, Weiterleitungen. Für IP-Ziele leer."""
    try:
        ipaddress.ip_address(host)
        return {}
    except ValueError:
        pass
    out = {"host": host, "warnings": []}
    with ThreadPoolExecutor(4) as ex:
        f_rdap = ex.submit(lambda: _safe(rdap_domain, host))
        f_dns = ex.submit(dns_records, host)
        f_tls = ex.submit(tls_info, host)
        f_http = ex.submit(lambda: _safe(http_chain, host))
        out["rdap"], out["dns"], out["tls"], out["http"] = f_rdap.result(), f_dns.result(), f_tls.result(), f_http.result()
    W = out["warnings"]
    reg = (out["rdap"] or {}).get("registered")
    if reg:
        try:
            dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - dt).days
            out["rdap"]["age_days"] = days
            if days < 30:
                W.append({"key": "warn_young_domain", "days": days})
        except Exception:
            pass
    tls = out["tls"]
    if tls.get("error"):
        W.append({"key": "warn_cert", "msg": tls["error"]})
    elif tls.get("days_left") is not None and tls["days_left"] < 0:
        W.append({"key": "warn_cert", "msg": "expired"})
    ch = (out["http"] or {}).get("chain", [])
    if ch:
        final = urlsplit(ch[-1]["url"]).hostname or ""
        if final and reg_domain(final) != reg_domain(host):
            W.append({"key": "warn_redirect_other", "host": final})
    return out


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception:
        return {}


# ------------------------------------------------------------------ Messung

def probe_stats(rtts: list, probes: int) -> dict:
    if not rtts:
        return {"loss_pct": 100.0}
    out = {"loss_pct": round((probes - len(rtts)) / probes * 100, 1),
           "rtt_min": round(min(rtts), 2), "rtt_avg": round(sum(rtts) / len(rtts), 2), "rtt_max": round(max(rtts), 2)}
    out["jitter_ms"] = round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0
    return out
