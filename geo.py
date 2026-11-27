"""IP-Anreicherung: Geolocation, ASN, Rechenzentrum-Hinweis, Reverse-DNS.

Nutzt ip-api.com (kostenlos, ohne Key, Batch bis 100 IPs). Die abgefragten
IP-Adressen werden dabei an diesen Dienst gesendet.
"""
import ipaddress
import json
from pathlib import Path
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DATA = Path(__file__).parent / "data"
CITY_DB = DATA / "GeoLite2-City.mmdb"
ASN_DB = DATA / "GeoLite2-ASN.mmdb"
_readers: dict = {}


def local_available() -> bool:
    return CITY_DB.exists()


def _reader(path: Path):
    if path not in _readers:
        import maxminddb
        _readers[path] = maxminddb.open_database(str(path))
    return _readers[path]


def _local_info(ip: str) -> dict:
    """Lokale MaxMind-Datenbank (keine Netzwerkabfrage)."""
    c = _reader(CITY_DB).get(ip) or {}
    if not c.get("location"):
        return {"ip": ip, "error": "not in local database"}
    name = lambda d: ((d or {}).get("names") or {}).get("en")
    info = {"ip": ip, "country": name(c.get("country")), "country_code": (c.get("country") or {}).get("iso_code"),
            "region": name((c.get("subdivisions") or [None])[0]), "city": name(c.get("city")),
            "lat": c["location"].get("latitude"), "lon": c["location"].get("longitude"), "datacenter": False, "hostname": ""}
    if ASN_DB.exists():
        a = _reader(ASN_DB).get(ip) or {}
        if a.get("autonomous_system_number"):
            org = a.get("autonomous_system_organization", "")
            info["asn"] = f"AS{a['autonomous_system_number']} {org}".strip()
            info["isp"] = org
            info["as_name"] = org
    return info


FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,hosting,reverse,query"
_cache: dict = {}


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def lookup(ips: list, local_only: bool = False) -> dict:
    """Gibt {ip: info-dict} zurück. Private/ungültige IPs bekommen nur Basisinfos."""
    result = {}
    todo = []
    for ip in dict.fromkeys(ips):
        if local_only and is_public(ip):
            result[ip] = _local_info(ip)
        elif ip in _cache:
            result[ip] = _cache[ip]
        elif is_public(ip):
            todo.append(ip)
        else:
            result[ip] = {"ip": ip, "private": True}

    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        body = json.dumps([{"query": ip, "fields": FIELDS} for ip in chunk]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                rows = json.load(r)
        except Exception as e:
            rows = [{"query": ip, "status": "fail", "message": str(e)} for ip in chunk]
        for row in rows:
            ip = row.get("query")
            if row.get("status") == "success":
                info = {
                    "ip": ip,
                    "country": row.get("country"),
                    "country_code": row.get("countryCode"),
                    "region": row.get("regionName"),
                    "city": row.get("city"),
                    "lat": row.get("lat"),
                    "lon": row.get("lon"),
                    "isp": row.get("isp"),
                    "org": row.get("org"),
                    "asn": row.get("as"),
                    "as_name": row.get("asname"),
                    "datacenter": bool(row.get("hosting")),
                }
                info["_rev"] = row.get("reverse") or ""
            else:
                info = {"ip": ip, "error": row.get("message", "unbekannt")}
            result[ip] = info

    if local_only:
        return result
    # Reverse-DNS parallel nachladen, wo ip-api keins lieferte
    need = [ip for ip, v in result.items() if "error" not in v and not v.get("private") and "hostname" not in v]
    with ThreadPoolExecutor(8) as ex:
        for ip, name in zip(need, ex.map(lambda x: result[x].pop("_rev", "") or _rdns(x), need)):
            result[ip]["hostname"] = name
    for ip in result:
        result[ip].pop("_rev", None)
        _cache[ip] = result[ip]
    return result


def my_public_ip() -> str:
    try:
        with urllib.request.urlopen("http://ip-api.com/json/?fields=query", timeout=8) as r:
            return json.load(r).get("query", "")
    except Exception:
        return ""
