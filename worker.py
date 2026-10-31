"""JaatFlix video relay for Wispbyte.

Render (the real backend) hands out links that point HERE (VIDEO_WORKER=https://this-server).

Two kinds of links:
  1. normal   e=<cdn url>           -> this server fetches that url from the CDN (with the right Referer) and streams it.
  2. resolve  e="mb:{...}" (Render has WORKER_RESOLVE=1)
              -> the link only says WHAT to play (subject / episode / quality).  THIS server asks MovieBox for the signed
                 video url itself, so the url is issued to - and fetched from - the SAME ip.  This is what makes
                 1080p and the HLS "streams" work (MovieBox ties those urls to the ip that asked for them).

No database, no login - only the signed links from Render (same LINK_SECRET).
"""
import asyncio
import gc
import hmac
import json
import os
import time
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

import worker_core as core

UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
ALT_UA = ("com.community.oneroom/50020131 (Linux; U; Android 10; en_IN; Redmi Note 7; "
          "Build/QKQ1.190910.002; Cronet/156.0.8078.25)")
DEFAULT_REFERER = os.getenv("DEFAULT_REFERER", "https://netfilm.world/")
CHECK_IP = os.getenv("WORKER_CHECK_IP", "0") == "1"        # 1 = the link only works from the ip it was made for
TRUST_PROXY = os.getenv("WORKER_TRUST_PROXY", "0") == "1"  # 1 only when a tunnel / proxy is in front of this server
UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY") or None       # optional http://user:pass@host:port for ALL upstream requests
ORIGINS = [o.strip() for o in os.getenv("WORKER_ORIGINS", "*").split(",") if o.strip()] or ["*"]

# ---- MovieBox (needed only for "resolve" links) ----
MB_API = os.getenv("MB_API", "https://h5-api.aoneroom.com/wefeed-h5api-bff")
MB_HOST = os.getenv("MB_HOST", "moviebox.ph")
IN_IP = os.getenv("IN_FAKE_IP", "49.205.120.45")
INH = {"X-Forwarded-For": IN_IP, "X-Real-IP": IN_IP, "CF-Connecting-IP": IN_IP, "CF-IPCountry": "IN"}
XCI = '{"timezone":"Asia/Kolkata"}'
BASE_H = {
    "User-Agent": UA, "Referer": "https://moviebox.ph/", "Origin": "https://moviebox.ph",
    "Accept": "application/json", "Content-Type": "application/json",
    "X-Request-Lang": "en", "X-Client-Info": XCI, "Accept-Language": "en-IN,en;q=0.9", **INH,
}
# other CDN edges - when the main host answers 426/427/403 to this ip, the same path+query is tried on these
FALLBACK_HOSTS = [h.strip() for h in os.getenv("FALLBACK_CDN_HOSTS", "cacdn.hakunaymatata.com,sbcdn5.hakunaymatata.com").split(",") if h.strip()]
CHUNK = int(os.getenv("RELAY_CHUNK", "262144"))           # bytes handed to the server per step (bigger = far less CPU; was ~16 KB TLS records)
HOST_TTL = int(os.getenv("HOST_TTL", "1800"))             # remember for this long which CDN host / UA worked
gc.set_threshold(50000, 30, 30)                           # fewer garbage-collector runs (the relay keeps almost no long-lived objects)
RESOLVE_TTL = int(os.getenv("RESOLVE_TTL", "600"))        # seconds a resolved video url is reused (mp4 = many Range requests)

app = FastAPI(title="JaatFlix relay", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_methods=["GET", "HEAD", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Type"],
)

_client = None
_tok = {"v": "", "t": 0.0}
_cache = {}      # spec json -> (time, url, referer)
_locks = {}      # spec json -> asyncio.Lock  (one resolve at a time per film)
_HOSTMAP = {}    # refused host -> (working host, user agent, expiry)
_PLCACHE = {}    # (url, link token) -> (time, rewritten playlist)
_STATS = {"resolve_ok": 0, "resolve_fail": 0, "cdn_fallback_ok": 0}


def client():
    global _client
    if _client is None:
        kw = {"proxy": UPSTREAM_PROXY} if UPSTREAM_PROXY else {}
        _client = httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(30, connect=10),
                                    limits=httpx.Limits(max_connections=60, max_keepalive_connections=30, keepalive_expiry=60), http2=False, **kw)
    return _client


def client_ip(request: Request):
    peer = request.client.host if request.client else ""
    if TRUST_PROXY:
        for h in ("cf-connecting-ip", "x-real-ip"):
            v = (request.headers.get(h) or "").strip()
            if v:
                return v
        v = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if v:
            return v
    return peer


def _host(u):
    try:
        return urlparse(u).netloc.split(":")[0]
    except Exception:
        return "?"


def _key(spec):
    return json.dumps(spec, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------------ MovieBox: token + play ----
async def _token(force=False):
    if not force and _tok["v"] and time.time() - _tok["t"] < 900:
        return _tok["v"]
    try:
        r = await client().get("%s/home?host=%s" % (MB_API, MB_HOST), headers=BASE_H)
        xu = r.headers.get("x-user")
        if xu:
            t = json.loads(xu).get("token")
            if t:
                _tok["v"], _tok["t"] = t, time.time()
    except Exception as ex:
        print("[relay] token failed:", repr(ex)[:120], flush=True)
    return _tok["v"]


_dom_c = {"v": "", "t": 0.0}


async def _domain():
    """MovieBox player domain (get-domain), cached 10 min"""
    if _dom_c["v"] and time.time() - _dom_c["t"] < 600:
        return _dom_c["v"]
    tok = await _token()
    h = {**BASE_H}
    if tok:
        h["Authorization"] = "Bearer " + tok
    dom = ""
    try:
        r = await client().get("%s/media-player/get-domain" % MB_API, headers=h)
        d = r.json().get("data")
        dom = d if isinstance(d, str) else ""
    except Exception as ex:
        print("[relay] get-domain failed:", repr(ex)[:120], flush=True)
    dom = (dom or "https://netfilm.world").rstrip("/")
    _dom_c["v"], _dom_c["t"] = dom, time.time()
    return dom


async def _mb(url, ref, need_resource=True):
    """MovieBox GET from THIS ip (token + India headers) -> data dict or {}"""
    tok = await _token()
    fresh_tok = False
    for attempt in range(4):
        h = {**BASE_H, "Referer": ref}
        h.pop("Content-Type", None)
        h.pop("Origin", None)
        if tok:
            h["Authorization"] = "Bearer " + tok
        try:
            r = await client().get(url, headers=h)
        except Exception as ex:
            print("[relay] MovieBox call failed:", repr(ex)[:120], flush=True)
            return {}
        if r.status_code == 429:
            await asyncio.sleep(2.5 * (attempt + 1))
            continue
        if r.status_code in (401, 403) and not fresh_tok:
            tok, fresh_tok = await _token(True), True
            continue
        if r.status_code != 200:
            print("[relay] MovieBox answered %s" % r.status_code, flush=True)
            return {}
        try:
            data = (r.json().get("data") or {})
        except Exception:
            return {}
        if need_resource and not data.get("hasResource") and not fresh_tok:   # one retry with a fresh token
            tok, fresh_tok = await _token(True), True
            continue
        return data
    return {}


def _play_urls(dom, s, d, se, ep):
    ref = "%s/spa/videoPlayPage/movies/%s?id=%s&type=/movie/detail&detailSe=%s&detailEp=%s&lang=en" % (dom, d, s, se, ep)
    return ref, "%s/wefeed-h5api-bff/subject/%s?subjectId=%s&se=%s&ep=%s&detailPath=%s"


async def _play(spec):
    """MovieBox play API, called from THIS ip -> data dict or {}"""
    dom = (spec.get("dom") or "https://netfilm.world").rstrip("/")
    s, d = spec.get("s"), spec.get("d")
    se, ep = int(spec.get("se") or 0), int(spec.get("ep") or 0)
    ref, tpl = _play_urls(dom, s, d, se, ep)
    return await _mb(tpl % (dom, "play", s, se, ep, d), ref)


def _pick(pd, spec):
    """the url the spec points at (hls item n / streams item n, falling back to the same quality)"""
    lst = (pd.get("hls") if spec.get("l") == "hls" else pd.get("streams")) or []
    n = int(spec.get("n") or 0)
    cand = lst[n] if 0 <= n < len(lst) else None
    if spec.get("l") != "hls":
        want = int(spec.get("r") or 0)
        if want and (not isinstance(cand, dict) or int(cand.get("resolutions") or 0) != want):
            for x in lst:
                if isinstance(x, dict) and int(x.get("resolutions") or 0) == want and x.get("url"):
                    cand = x
                    break
    if cand is None and lst:
        cand = lst[0]
    if isinstance(cand, dict):
        return cand.get("url") or ""
    return cand or ""


async def resolve(spec, fresh=False):
    """-> (cdn url, referer) or ("", "")"""
    key = _key(spec)
    hit = _cache.get(key)
    if hit and not fresh and time.time() - hit[0] < RESOLVE_TTL:
        return hit[1], hit[2]
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = _cache.get(key)
        if hit and not fresh and time.time() - hit[0] < RESOLVE_TTL:
            return hit[1], hit[2]
        pd = await _play(spec)
        u = _pick(pd, spec)
        if not u:
            _STATS["resolve_fail"] += 1
            print("[relay] resolve: MovieBox gave no stream (hasResource=%s hls=%d streams=%d)" % (
                pd.get("hasResource"), len(pd.get("hls") or []), len(pd.get("streams") or [])), flush=True)
            return "", ""
        ref = (spec.get("dom") or "https://netfilm.world").rstrip("/") + "/"
        _cache[key] = (time.time(), u, ref)
        _STATS["resolve_ok"] += 1
        if len(_cache) > 300:                       # keep memory small (512 MB server)
            for k in sorted(_cache, key=lambda k: _cache[k][0])[:100]:
                _cache.pop(k, None)
                _locks.pop(k, None)
        return u, ref


# ------------------------------------------------------------------ routes ----
@app.get("/")
async def root():
    return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})


def _relay_ok(request):
    k = os.getenv("RELAY_KEY", "")
    return (not k) or hmac.compare_digest((request.headers.get("x-relay-key") or "").encode(), k.encode())


async def _relay_data(request, kind, subjectId, se, ep, detailPath):
    no = {"Cache-Control": "no-store"}
    if not _relay_ok(request):
        return JSONResponse({"ok": False}, status_code=403, headers=no)
    dom = await _domain()
    ref, tpl = _play_urls(dom, subjectId, detailPath, se, ep)
    data = await _mb(tpl % (dom, kind, subjectId, se, ep, detailPath), ref, need_resource=(kind == "play"))
    ok = bool(data.get("hasResource")) if kind == "play" else bool(data.get("downloads"))
    return JSONResponse({"ok": ok, "data": data, "domain": dom}, headers=no)


@app.get("/stream")
async def relay_stream(request: Request, subjectId: str = "", se: int = 0, ep: int = 0, detailPath: str = ""):
    """Render asks HERE for the play data, so the stream urls are issued to THIS ip (the one that fetches them later)"""
    return await _relay_data(request, "play", subjectId, se, ep, detailPath)


@app.get("/download")
async def relay_download(request: Request, subjectId: str = "", se: int = 0, ep: int = 0, detailPath: str = ""):
    return await _relay_data(request, "download", subjectId, se, ep, detailPath)


@app.get("/health")
async def health():
    return {"ok": True, "secret_set": bool(core.secret()), "check_ip": CHECK_IP, "trust_proxy": TRUST_PROXY,
            "resolve": True, "stats": _STATS}


async def _fetch(u, ref, rng, ua=UA):
    h = {"User-Agent": ua, "Referer": ref, "Origin": ref.rstrip("/"), "Accept": "*/*", "Accept-Encoding": "identity"}
    if rng:
        h["Range"] = rng
    c = client()
    return await c.send(c.build_request("GET", u, headers=h), stream=True)


async def _open(u, ref, rng, spec=None):
    """open the CDN url.  On 401/403/404/410/426/427/451: (resolve links) a fresh url, then the other CDN hosts / alternate UA."""
    p0 = urlparse(u)
    mem = _HOSTMAP.get(p0.netloc.split(":")[0])
    if mem and time.time() < mem[2]:                           # this host was refused before and an alternative worked: go straight there
        cand0 = urlunparse((p0.scheme, mem[0], p0.path, p0.params, p0.query, p0.fragment))
        try:
            r = await _fetch(cand0, ref, rng, mem[1])
            if r.status_code < 400:
                return r, cand0
            await r.aclose()
        except Exception:
            pass
        _HOSTMAP.pop(p0.netloc.split(":")[0], None)
    r = await _fetch(u, ref, rng)
    if r.status_code < 400:
        return r, u
    code = r.status_code
    await r.aclose()
    print("[relay] CDN answered %s for %s" % (code, _host(u)), flush=True)
    if code not in (401, 403, 404, 410, 426, 427, 451):
        return await _fetch(u, ref, rng), u
    if spec is not None:                                       # the url may simply have expired -> ask MovieBox again
        u2, ref2 = await resolve(spec, fresh=True)
        if u2:
            u, ref = u2, ref2
            r = await _fetch(u, ref, rng)
            if r.status_code < 400:
                return r, u
            await r.aclose()
    p = urlparse(u)
    for host in FALLBACK_HOSTS:
        if host == p.netloc.split(":")[0]:
            continue
        cand = urlunparse((p.scheme, host, p.path, p.params, p.query, p.fragment))
        for ua in (UA, ALT_UA):
            try:
                r = await _fetch(cand, ref, rng, ua)
            except Exception:
                continue
            if r.status_code < 400:
                _STATS["cdn_fallback_ok"] += 1
                _HOSTMAP[p.netloc.split(":")[0]] = (host, ua, time.time() + HOST_TTL)
                print("[relay] fallback host worked: %s -> %s" % (_host(u), host), flush=True)
                if spec is not None:                           # remember it, later Range requests go straight there
                    _cache[_key(spec)] = (time.time(), cand, ref)
                return r, cand
            await r.aclose()
    return await _fetch(u, ref, rng), u                        # give the player the real error


@app.get("/p")
async def relay(request: Request, e: str = "", t: str = "", q: str = ""):
    no = {"Cache-Control": "no-store"}
    u = core.dec(e) if e else ""
    if not u:
        return Response("forbidden", status_code=403, headers=no)
    spec = None
    if u.startswith("mb:"):
        try:
            spec = json.loads(u[3:])
            assert isinstance(spec, dict)
        except Exception:
            return Response("forbidden", status_code=403, headers=no)
    elif not core.safe_url(u):
        return Response("forbidden", status_code=403, headers=no)
    p, why = core.check(u, t, client_ip(request), request.headers.get("x-device", ""), CHECK_IP)
    if not p:
        print("[relay] refused:", why, flush=True)
        return Response("forbidden", status_code=403, headers=no)
    ref = (core.dec(q) if q else "") or DEFAULT_REFERER
    if not ref.lower().startswith(("http://", "https://")):
        ref = DEFAULT_REFERER
    if spec is not None:
        u, ref_mb = await resolve(spec)
        if not u:
            return Response("no stream", status_code=502, headers=no)
        ref = ref_mb or ref
        if not core.safe_url(u):
            return Response("forbidden", status_code=403, headers=no)
    try:
        r, u = await _open(u, ref, request.headers.get("range"), spec)
    except Exception as ex:
        print("[relay] upstream failed:", repr(ex)[:160], flush=True)
        return Response("bad gateway", status_code=502, headers=no)
    ct = r.headers.get("content-type", "").lower()
    if r.status_code == 200 and ("mpegurl" in ct or u.split("?")[0].lower().endswith(".m3u8")):
        ck = (u, t, q)
        hit = _PLCACHE.get(ck)
        if hit and time.time() - hit[0] < 120:                 # a retry / second viewer: no rewrite, no CDN read
            await r.aclose()
            return Response(hit[1], media_type="application/vnd.apple.mpegurl", headers=no)
        try:
            text = (await r.aread()).decode("utf-8", "ignore")
        finally:
            await r.aclose()
        body = core.rewrite_m3u8(text, str(r.url), p, q)
        if len(_PLCACHE) > 60:
            for k_ in sorted(_PLCACHE, key=lambda k: _PLCACHE[k][0])[:30]:
                _PLCACHE.pop(k_, None)
        _PLCACHE[ck] = (time.time(), body)
        return Response(body, media_type="application/vnd.apple.mpegurl", headers=no)
    keep = {k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-length", "content-range", "accept-ranges")}
    if r.status_code in (200, 206):
        keep["Cache-Control"] = "private, max-age=1800"          # seek back / retry is answered by the browser, not by this server
    else:
        keep["Cache-Control"] = "no-store"

    async def gen():
        try:
            async for chunk in r.aiter_raw(CHUNK):
                yield chunk
        finally:
            await r.aclose()
    return StreamingResponse(gen(), status_code=r.status_code, headers=keep)
