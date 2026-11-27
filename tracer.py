"""Traceroute (Webadresse/IP) und Received-Header-Parser (E-Mail)."""
import email
import email.policy
import ipaddress
import re
import socket
import subprocess
import sys
from email.utils import parsedate_to_datetime

from intel import probe_stats

class TraceError(ValueError):
    """Fehler mit Übersetzungsschlüssel (siehe static/i18n.json)."""

    def __init__(self, key: str, **kw):
        super().__init__(key)
        self.key, self.kw = key, kw


PROBES = 4
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def normalize_target(raw: str) -> str:
    """Akzeptiert URL, Domain oder IP und liefert einen validierten Host."""
    t = raw.strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/")[0].split("?")[0]
    if t.startswith("["):  # [v6]:port
        t = t[1:].split("]")[0]
    elif t.count(":") == 1:
        t = t.split(":")[0]
    t = t.rstrip(".")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if not HOST_RE.match(t) or t.startswith("-"):
        raise TraceError("err_invalid_target", target=raw)
    return t


def resolve(host: str, mode: str = "auto") -> str:
    """mode: auto (IPv4 bevorzugt, sonst IPv6), 4 oder 6."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None  # Hostname, wird unten aufgelöst
    if ip is not None:
        if (mode == "4" and ip.version != 4) or (mode == "6" and ip.version != 6):
            raise TraceError("err_not_version", host=host, v=mode)
        return host
    families = {"4": [socket.AF_INET], "6": [socket.AF_INET6], "auto": [socket.AF_INET, socket.AF_INET6]}[mode]
    for fam in families:
        try:
            return socket.getaddrinfo(host, None, fam)[0][4][0]
        except socket.gaierror:
            continue
    raise TraceError("err_no_address", host=host, v="4/6" if mode == "auto" else mode)


def _no_traceroute_hint() -> str:
    if sys.platform.startswith("linux"):
        return "sudo apt install traceroute (Debian/Ubuntu)  |  sudo dnf install traceroute (Fedora)"
    return "traceroute"


def traceroute(host: str, max_hops: int = 30, mode: str = "auto") -> list:
    ip = resolve(host, mode)
    v6 = ipaddress.ip_address(ip).version == 6
    kw = {}
    probes = PROBES
    if sys.platform == "win32":  # tracert: feste 3 Messungen, Zeitlimit in Millisekunden
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", "-6" if v6 else "-4", ip]
        probes = 3
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    elif sys.platform == "darwin":
        cmd = ["traceroute6" if v6 else "traceroute", "-n", "-q", str(PROBES), "-w", "1", "-m", str(max_hops), ip]
    else:  # Linux u. a.
        cmd = ["traceroute"] + (["-6"] if v6 else []) + ["-n", "-q", str(PROBES), "-w", "1", "-m", str(max_hops), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300, **kw)
    except FileNotFoundError:
        raise TraceError("err_no_traceroute", hint=_no_traceroute_hint())
    hops = parse_traceroute(proc.stdout, probes)
    if not hops:
        err = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else "keine Ausgabe")
    return hops


def parse_traceroute(out: str, probes: int = 4) -> list:
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        n, rest = int(m.group(1)), m.group(2)
        ips = []
        for tok in rest.split():
            tok = tok.strip("()[]")
            try:
                ipaddress.ip_address(tok)
                ips.append(tok)
            except ValueError:
                pass
        rtts = [float(x) for x in re.findall(r"([\d.]+)\s*ms", rest)]
        hop = {
            "hop": n,
            "ip": ips[0] if ips else None,
            "rtt_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "timeout": not ips,
            "probes": probes,
        }
        hop.update(probe_stats(rtts, probes))
        hops.append(hop)
    return hops


# ---------------------------------------------------------------- E-Mail

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
IPV6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,39})\]")


def _ips_in(text: str) -> list:
    found = IPV4.findall(text) + IPV6.findall(text)
    out = []
    for f in found:
        try:
            ipaddress.ip_address(f)
            out.append(f)
        except ValueError:
            pass
    return list(dict.fromkeys(out))


def parse_headers(raw: str) -> dict:
    msg = email.message_from_string(raw, policy=email.policy.default)
    received = msg.get_all("Received") or []
    hops = []
    for r in reversed(received):  # unterster Header = ältester Hop
        r = " ".join(str(r).split())
        frm = re.search(r"from\s+(\S+)", r, re.I)
        by = re.search(r"by\s+(\S+)", r, re.I)
        with_ = re.search(r"with\s+(\S+)", r, re.I)
        date = r.rsplit(";", 1)[-1].strip() if ";" in r else ""
        try:
            ts = parsedate_to_datetime(date).isoformat()
        except Exception:
            ts = date
        # IP des sendenden Servers steht meist im from-Teil
        from_part = r.split(" by ", 1)[0]
        ips = _ips_in(from_part) or _ips_in(r)
        hops.append({
            "from_host": frm.group(1) if frm else None,
            "by_host": by.group(1) if by else None,
            "protocol": with_.group(1) if with_ else None,
            "timestamp": ts,
            "ips": ips,
            "raw": r[:500],
        })
    auth = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))
    info = {
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "subject": str(msg.get("Subject", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "x_originating_ip": str(msg.get("X-Originating-IP", "")).strip("[] "),
        "spf": (re.search(r"spf=(\w+)", auth) or [None, None])[1],
        "dkim": (re.search(r"dkim=(\w+)", auth) or [None, None])[1],
        "dmarc": (re.search(r"dmarc=(\w+)", auth) or [None, None])[1],
    }
    warnings = []
    if not hops:
        warnings.append({"key": "warn_no_received"})
    if info["spf"] and info["spf"] != "pass":
        warnings.append({"key": "warn_auth", "proto": "SPF", "val": info["spf"]})
    if info["dkim"] and info["dkim"] != "pass":
        warnings.append({"key": "warn_auth", "proto": "DKIM", "val": info["dkim"]})
    if info["dmarc"] and info["dmarc"] != "pass":
        warnings.append({"key": "warn_auth", "proto": "DMARC", "val": info["dmarc"]})
    return {"info": info, "hops": hops, "warnings": warnings}
