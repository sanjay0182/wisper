"""Link crypto + playlist rewriting for the Wispbyte video relay.  Standard library only, NO database.

It speaks exactly the same link format as protect.py on Render (same LINK_SECRET):
    /p?e=<url, encrypted>&t=<payload>.<signature>[&q=<referer, encrypted>]
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from urllib.parse import quote, urljoin, urlparse


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def secret():
    return os.environ.get("LINK_SECRET", "").encode()


def _ks(nonce, n):
    k = hashlib.sha256(b"jf-enc|" + secret()).digest()
    return b"".join(hmac.new(k, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest() for i in range((n + 31) // 32))


def enc(u):
    b = u.encode("utf-8")
    n = os.urandom(12)
    return _b64(n + bytes(x ^ y for x, y in zip(b, _ks(n, len(b)))))


def dec(e):
    try:
        raw = _unb64(e)
        n, ct = raw[:12], raw[12:]
        return bytes(x ^ y for x, y in zip(ct, _ks(n, len(ct)))).decode("utf-8")
    except Exception:
        return ""


def _sig(payload, u):
    return _b64(hmac.new(secret(), (payload + "|" + u).encode("utf-8", "ignore"), hashlib.sha256).digest())[:30]


def dev_hash(dev):
    return _b64(hashlib.sha256(dev.encode("utf-8", "ignore")).digest())[:12] if dev else ""


_DEV_RE = re.compile(r"^[A-Za-z0-9_-]{8,40}$")


def device_id(header_value):
    v = (header_value or "").strip()
    return v if _DEV_RE.match(v) else ""


def ip_key(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 6:
            return "v6:" + str(ipaddress.ip_network(ip + "/64", strict=False).network_address)
    except Exception:
        pass
    return ip


def safe_url(u):
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        h = p.hostname.lower()
        if h == "localhost" or h.endswith(".local") or h.endswith(".internal"):
            return False
        try:
            a = ipaddress.ip_address(h)
            if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified:
                return False
        except ValueError:
            pass
        return True
    except Exception:
        return False


def parse(t, u):
    """signature checked -> claims dict, or None"""
    try:
        payload, sig = (t or "").split(".", 1)
        if not hmac.compare_digest(sig, _sig(payload, u)):
            return None
        d = json.loads(_unb64(payload))
        return {"k": d["k"], "s": d["s"], "i": d["i"], "e": float(d["e"]), "d": d.get("d", "")}
    except Exception:
        return None


def check(u, t, client_ip="", dev_header="", check_ip=False):
    """-> (claims | None, reason)"""
    if not secret():
        return None, "no LINK_SECRET set"
    p = parse(t, u)
    if not p or p["k"] != "s":
        return None, "bad"
    if time.time() > p["e"]:
        return None, "expired"
    if p["d"] and dev_hash(device_id(dev_header)) != p["d"]:
        return None, "device"
    if check_ip and ip_key(client_ip) != p["i"]:
        return None, "ip"
    return p, ""


def mint(p, u):
    """a fresh link for u (a url found inside a playlist) with the same session / expiry / device as the playlist's own link"""
    claims = {"k": "s", "s": p["s"], "i": p["i"], "e": round(p["e"])}
    if p.get("d"):
        claims["d"] = p["d"]
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    return "/p?e=%s&t=%s.%s" % (enc(u), payload, _sig(payload, u))


def rewrite_m3u8(text, base_url, p, q=""):
    def fix(x):
        l = mint(p, urljoin(base_url, x.strip()))
        return l + ("&q=" + quote(q, safe="") if q else "")
    out = []
    for ln in text.splitlines():
        if ln.startswith("#"):
            ln = re.sub(r'URI="([^"]+)"', lambda m: 'URI="' + fix(m.group(1)) + '"', ln)
        elif ln.strip():
            ln = fix(ln)
        out.append(ln)
    return "\n".join(out)
