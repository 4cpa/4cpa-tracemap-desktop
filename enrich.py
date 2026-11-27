"""Zusatzinfos: Rechenzentren (PeeringDB) und Abuse-Kontakt (RDAP)."""
import ipaddress
import json
import math
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor

_net_cache: dict = {}
_abuse_cache: dict = {}


def _get(url: str, headers=None, timeout=8):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "tracemap"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _facilities(asn: int) -> list:
    if asn in _net_cache:
        return _net_cache[asn]
    facs = []
    try:
        nets = _get(f"https://www.peeringdb.com/api/net?asn={asn}")["data"]
        if nets:
            nf = _get(f"https://www.peeringdb.com/api/netfac?net_id={nets[0]['id']}&limit=300")["data"]
            ids = ",".join(str(x["fac_id"]) for x in nf)
            if ids:
                for f in _get(f"https://www.peeringdb.com/api/fac?id__in={ids}&depth=0")["data"]:
                    if f.get("latitude") is not None and f.get("longitude") is not None:
                        facs.append({"name": f["name"], "city": f.get("city"), "country": f.get("country"),
                                     "lat": f["latitude"], "lon": f["longitude"], "operator": f.get("org_name")})
    except Exception:
        pass
    _net_cache[asn] = facs
    return facs


def _dist(a, b, c, d) -> float:
    p = math.pi / 180
    h = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742 * math.asin(math.sqrt(h))


_bootstrap: dict = {}


def _rdap_base(ip: str):
    """Findet über das IANA-Bootstrap den zuständigen RIR-RDAP-Server (statt rdap.org, das drosselt)."""
    a = ipaddress.ip_address(ip)
    key = f"ipv{a.version}"
    if key not in _bootstrap:
        _bootstrap[key] = _get(f"https://data.iana.org/rdap/{key}.json", timeout=10)["services"]
    best, best_len = None, -1
    for prefixes, urls in _bootstrap[key]:
        for p in prefixes:
            n = ipaddress.ip_network(p)
            if a in n and n.prefixlen > best_len:
                best, best_len = urls[0], n.prefixlen
    return best


def _abuse(ip: str) -> str:
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    mail = ""
    ok = False
    try:
        base = _rdap_base(ip)
        d = _get(f"{base.rstrip('/')}/ip/{ip}", {"Accept": "application/rdap+json", "User-Agent": "tracemap"}, 10)
        ok = True

        def walk(ents):
            for e in ents or []:
                if "abuse" in e.get("roles", []):
                    for item in (e.get("vcardArray") or [None, []])[1]:
                        if item[0] == "email":
                            return item[3]
                m = walk(e.get("entities"))
                if m:
                    return m
            return ""
        mail = walk(d.get("entities"))
    except Exception:
        pass
    if ok:  # Fehlschläge (z. B. Drosselung) nicht dauerhaft cachen
        _abuse_cache[ip] = mail
    return mail


def enrich(infos: dict) -> None:
    """Ergänzt infos in-place um nächstgelegenes Rechenzentrum und Abuse-Mail."""
    public = [v for v in infos.values() if v.get("lat") is not None]
    asns = {int(m.group(1)) for v in public if (m := re.match(r"AS(\d+)", v.get("asn") or ""))}
    with ThreadPoolExecutor(6) as ex:
        facs = dict(zip(asns, ex.map(_facilities, asns)))
        abuse = dict(zip([v["ip"] for v in public], ex.map(_abuse, [v["ip"] for v in public])))
    for v in public:
        m = re.match(r"AS(\d+)", v.get("asn") or "")
        fl = facs.get(int(m.group(1)), []) if m else []
        if fl:
            best = min(fl, key=lambda f: _dist(v["lat"], v["lon"], f["lat"], f["lon"]))
            km = round(_dist(v["lat"], v["lon"], best["lat"], best["lon"]))
            v["facility"] = {**best, "distance_km": km}
            v["facility_count"] = len(fl)
        if abuse.get(v["ip"]):
            v["abuse_contact"] = abuse[v["ip"]]
