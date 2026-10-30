"""JaatFlix video relay for Wispbyte - does what the Cloudflare Worker did.

Render (the real backend) hands out links that point HERE (VIDEO_WORKER=https://this-server).
This server checks the link, fetches the film from the CDN with the right Referer and streams it
to the viewer.  No database, no login - only the signed links from Render (same LINK_SECRET).
"""
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response, StreamingResponse

import worker_core as core

UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
DEFAULT_REFERER = os.getenv("DEFAULT_REFERER", "https://netfilm.world/")
CHECK_IP = os.getenv("WORKER_CHECK_IP", "0") == "1"        # 1 = the link only works from the ip it was made for
TRUST_PROXY = os.getenv("WORKER_TRUST_PROXY", "0") == "1"  # 1 only when a tunnel / proxy is in front of this server
UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY") or None       # optional http://user:pass@host:port for the CDN requests
ORIGINS = [o.strip() for o in os.getenv("WORKER_ORIGINS", "*").split(",") if o.strip()] or ["*"]

app = FastAPI(title="JaatFlix relay", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_methods=["GET", "HEAD", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Type"],
)

_client = None


def client():
    global _client
    if _client is None:
        kw = {"proxy": UPSTREAM_PROXY} if UPSTREAM_PROXY else {}
        _client = httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(30, connect=10),
                                    limits=httpx.Limits(max_connections=60, max_keepalive_connections=20), **kw)
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


@app.get("/")
async def root():
    return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})


@app.get("/health")
async def health():
    return {"ok": True, "secret_set": bool(core.secret()), "check_ip": CHECK_IP, "trust_proxy": TRUST_PROXY}


@app.get("/p")
async def relay(request: Request, e: str = "", t: str = "", q: str = ""):
    no = {"Cache-Control": "no-store"}
    u = core.dec(e) if e else ""
    if not u or not core.safe_url(u):
        return Response("forbidden", status_code=403, headers=no)
    p, why = core.check(u, t, client_ip(request), request.headers.get("x-device", ""), CHECK_IP)
    if not p:
        print("[relay] refused:", why, flush=True)
        return Response("forbidden", status_code=403, headers=no)
    ref = (core.dec(q) if q else "") or DEFAULT_REFERER
    if not ref.lower().startswith(("http://", "https://")):
        ref = DEFAULT_REFERER
    h = {"User-Agent": UA, "Referer": ref, "Origin": ref.rstrip("/"), "Accept": "*/*"}
    if request.headers.get("range"):
        h["Range"] = request.headers["range"]
    c = client()
    try:
        r = await c.send(c.build_request("GET", u, headers=h), stream=True)
    except Exception as ex:
        print("[relay] upstream failed:", repr(ex)[:160], flush=True)
        return Response("bad gateway", status_code=502, headers=no)
    ct = r.headers.get("content-type", "").lower()
    if r.status_code == 200 and ("mpegurl" in ct or u.split("?")[0].lower().endswith(".m3u8")):
        try:
            text = (await r.aread()).decode("utf-8", "ignore")
        finally:
            await r.aclose()
        body = core.rewrite_m3u8(text, str(r.url), p, q)
        return Response(body, media_type="application/vnd.apple.mpegurl", headers=no)
    if r.status_code >= 400:
        print("[relay] CDN answered %s for %s" % (r.status_code, u.split("?")[0].split("/")[2] if "//" in u else "?"), flush=True)
    keep = {k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-length", "content-range", "accept-ranges")}

    async def gen():
        try:
            async for chunk in r.aiter_raw():
                yield chunk
        finally:
            await r.aclose()
    return StreamingResponse(gen(), status_code=r.status_code, headers=keep)
