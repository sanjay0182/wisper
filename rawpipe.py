"""Raw pipe: the lightest possible video relay.

The browser asks   GET /p?e=...&t=...   (a signed link made by Render).
This module
  1. reads ONLY the request head (a few hundred bytes),
  2. checks the signature, swaps the headers (Referer / User-Agent ...),
  3. opens one TLS connection to the CDN, sends the new head,
  4. reads the CDN's answer head and then copies the body bytes to the browser
     with plain read()/write() - no HTTP framework, no parsing of the video.

Anything it cannot do the simple way is handed to the normal code in worker.py
(playlists that must be rewritten, 4xx from the CDN that need a fresh link or another
CDN host, redirects).  Every other path (/, /health, /stream ...) is passed on, unchanged,
to the normal app listening on 127.0.0.1.

Every answer closes its connection (Connection: close) so that both ends always know where
the body ends without parsing it.
"""
import asyncio
import json
import os
import ssl
import time
from urllib.parse import parse_qs, quote, urlsplit

import worker
import worker_core as core

CHUNK = worker.CHUNK
HEAD_LIMIT = 32768
VERIFY_TLS = os.getenv("RAW_VERIFY_TLS", "1") != "0"
_ctx = ssl.create_default_context()
if not VERIFY_TLS:
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
STATS = {"raw": 0, "fallback": 0, "pass": 0, "bytes": 0, "new_conn": 0, "reused": 0, "http": 0}

# ---- upstream connection pool: a TLS handshake + certificate check per request is the most expensive thing on a slow CPU ----
_POOL = {}
POOL_TTL = int(os.getenv("POOL_TTL", "20"))
POOL_MAX = int(os.getenv("POOL_MAX", "4"))

# ---- http first: if the CDN accepts plain http:// the relay needs no TLS decrypt at all (the biggest CPU cost) ----
# HTTP_FIRST=1 (default) / 0 = always https.  The result is remembered per CDN host for HTTP_TTL seconds (default 24 h):
#   works -> every request goes over http for 24 h ; refused -> every request goes over https for 24 h ; then ONE new test.
# If a single http request fails while http is marked "works", only THAT request is repeated over https (the mark stays).
HTTP_FIRST = os.getenv("HTTP_FIRST", "1") != "0"
HTTP_TTL = int(os.getenv("HTTP_TTL", "86400"))
_HTTP_MEM = {}          # host -> (True/False, time of the test)


def _http_mode(host):
    """'test' (no fresh result: try http now), 'http' (works), 'https' (refused)"""
    m = _HTTP_MEM.get(host)
    if not m or time.time() - m[1] > HTTP_TTL:
        return "test"
    return "http" if m[0] else "https"


def _to_http(sp):
    """same url with http:// (default port 80; an explicit non-443 port is kept)"""
    host = sp.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    port = sp.port
    netloc = host + (":%d" % port if port and port != 443 else "")
    return urlsplit("http://" + netloc + (sp.path or "/") + (("?" + sp.query) if sp.query else ""))


def _pool_key(sp):
    return (sp.scheme, sp.hostname, sp.port or (443 if sp.scheme == "https" else 80))


async def _acquire(sp, fresh=False):
    """-> (reader, writer, reused)"""
    key = _pool_key(sp)
    lst = _POOL.get(key) or []
    while lst and not fresh:
        r, w, t = lst.pop()
        if time.time() - t < POOL_TTL and not w.is_closing() and not r.at_eof():
            STATS["reused"] += 1
            return r, w, True
        try:
            w.close()
        except Exception:
            pass
    port = key[2]
    r, w = await asyncio.wait_for(asyncio.open_connection(
        sp.hostname, port, ssl=_ctx if sp.scheme == "https" else None,
        server_hostname=sp.hostname if sp.scheme == "https" else None, limit=CHUNK * 2), 10)
    STATS["new_conn"] += 1
    return r, w, False


def _release(sp, r, w):
    key = _pool_key(sp)
    lst = _POOL.setdefault(key, [])
    if len(lst) < POOL_MAX and not w.is_closing():
        lst.append((r, w, time.time()))
    else:
        try:
            w.close()
        except Exception:
            pass


async def stats_loop():
    """one line every 10 s while video moves: where the CPU goes, in numbers"""
    last = dict(STATS)
    t0, c0 = time.time(), time.process_time()
    while True:
        await asyncio.sleep(10)
        now, cn = time.time(), time.process_time()
        d = {k: STATS[k] - last.get(k, 0) for k in STATS}
        last = dict(STATS)
        if d["raw"] or d["fallback"] or d["pass"]:
            mb = d["bytes"] / 1048576.0
            cpu = (cn - c0) / max(0.001, now - t0) * 100
            print("[cpu] %ds: cpu=%d%% requests=%d (pipe=%d careful=%d app=%d) data=%.1fMB (%.2f cpu-sec/MB) new_tls=%d reused=%d http_pipe=%d" % (
                now - t0, cpu, d["raw"] + d["fallback"] + d["pass"], d["raw"], d["fallback"], d["pass"], mb,
                ((cn - c0) / mb) if mb else 0, d["new_conn"], d["reused"], d["http"]), flush=True)
        t0, c0 = now, cn


_CORS_EXPOSE = "Content-Length, Content-Range, Accept-Ranges, Content-Type"


def _cors(origin):
    if "*" in worker.ORIGINS:
        return "Access-Control-Allow-Origin: *\r\n"
    if origin and origin in worker.ORIGINS:
        return "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\n" % origin
    return ""


def _parse_head(raw):
    """-> (method, target, version, [(name, value)...]) or None"""
    try:
        lines = raw.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        hdr = []
        for ln in lines[1:]:
            if not ln:
                continue
            k, _, v = ln.partition(":")
            hdr.append((k.strip(), v.strip()))
        return method, target, version, hdr
    except Exception:
        return None


def _get(hdr, name, default=""):
    n = name.lower()
    for k, v in hdr:
        if k.lower() == n:
            return v
    return default


def _client_ip(hdr, peer):
    if worker.TRUST_PROXY:
        for h in ("cf-connecting-ip", "x-real-ip"):
            v = _get(hdr, h).strip()
            if v:
                return v
        v = _get(hdr, "x-forwarded-for").split(",")[0].strip()
        if v:
            return v
    return peer


async def _send_simple(writer, code, text, origin="", extra=""):
    body = text.encode()
    head = ("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nCache-Control: no-store\r\n%s%sConnection: close\r\n\r\n"
            % (code, {200: "OK", 204: "No Content", 403: "Forbidden", 502: "Bad Gateway", 400: "Bad Request"}.get(code, "Error"),
               len(body), _cors(origin), extra)).encode()
    writer.write(head + body)
    await writer.drain()


async def _splice(reader, writer, head, hdr, internal_port):
    """not a /p link: give the whole connection to the normal app (Connection: close so the next request comes back here)"""
    STATS["pass"] += 1
    try:
        ur, uw = await asyncio.open_connection("127.0.0.1", internal_port, limit=CHUNK * 2)
    except Exception:
        await _send_simple(writer, 502, "app not reachable")
        return
    lines = head.decode("latin-1").split("\r\n")
    keep = [lines[0]] + [ln for ln in lines[1:] if ln and ln.split(":", 1)[0].strip().lower() not in ("connection", "keep-alive", "proxy-connection")]
    keep.append("Connection: close")
    uw.write(("\r\n".join(keep) + "\r\n\r\n").encode("latin-1"))
    buffered = getattr(reader, "_buffer", b"")
    if buffered:
        uw.write(bytes(buffered))

    async def pump(src, dst):
        try:
            while True:
                d = await src.read(CHUNK)
                if not d:
                    break
                dst.write(d)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(pump(reader, uw), pump(ur, writer))


async def _fallback(writer, u, ref, rng, spec, is_head, origin):
    """the normal (httpx) path: redirects, fresh links, other CDN hosts, playlists"""
    STATS["fallback"] += 1
    r, u2 = await worker._open(u, ref, rng, spec)
    ct = r.headers.get("content-type", "").lower()
    try:
        if r.status_code == 200 and ("mpegurl" in ct or u2.split("?")[0].lower().endswith(".m3u8")):
            return r, u2, True
        keep = [(k, v) for k, v in r.headers.items() if k.lower() in ("content-type", "content-length", "content-range", "accept-ranges")]
        cc = "private, max-age=1800" if r.status_code in (200, 206) else "no-store"
        head = "HTTP/1.1 %d %s\r\n" % (r.status_code, r.reason_phrase or "OK")
        head += "".join("%s: %s\r\n" % kv for kv in keep) + "Cache-Control: %s\r\n" % cc + _cors(origin)
        head += "Access-Control-Expose-Headers: %s\r\nConnection: close\r\n\r\n" % _CORS_EXPOSE
        writer.write(head.encode("latin-1"))
        if not is_head:
            async for chunk in r.aiter_raw(CHUNK):
                writer.write(chunk)
                STATS["bytes"] += len(chunk)
                await writer.drain()
        else:
            await writer.drain()
    finally:
        if not (r.status_code == 200 and ("mpegurl" in ct or u2.split("?")[0].lower().endswith(".m3u8"))):
            await r.aclose()
    return None, u2, False


async def _playlist(writer, r, u2, p, q, t, origin):
    """playlists are small text files: rewritten by the normal code"""
    ck = (u2, t, q)
    hit = worker._PLCACHE.get(ck)
    if hit and time.time() - hit[0] < 120:
        body = hit[1]
        await r.aclose()
    else:
        try:
            text = (await r.aread()).decode("utf-8", "ignore")
        finally:
            await r.aclose()
        body = core.rewrite_m3u8(text, str(r.url), p, q)
        worker._PLCACHE[ck] = (time.time(), body)
    b = body.encode()
    head = ("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nContent-Length: %d\r\nCache-Control: no-store\r\n%s"
            "Access-Control-Expose-Headers: %s\r\nConnection: close\r\n\r\n" % (len(b), _cors(origin), _CORS_EXPOSE)).encode()
    writer.write(head + b)
    await writer.drain()


async def _open_pipe(csp, method, ref, rng):
    """open (or reuse) a connection to the CDN for csp, send the head, read the answer head.
    -> (reader, writer, status_parts, response_headers) when the answer is a plain 200/206 body the pipe can copy,
       None otherwise (error, 4xx/5xx, redirect, playlist). A connection that is not usable is closed here."""
    was_reused = False
    for attempt in (0, 1):
        ur = uw = None
        was_reused = False
        try:
            ur, uw, was_reused = await _acquire(csp, fresh=bool(attempt))
            rq = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferer: %s\r\nOrigin: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n" % (
                method, (csp.path or "/") + (("?" + csp.query) if csp.query else ""), csp.netloc, worker.UA, ref, ref.rstrip("/"))
            if rng:
                rq += "Range: %s\r\n" % rng
            uw.write((rq + "Connection: keep-alive\r\n\r\n").encode("latin-1"))
            raw = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), 20)
            st = raw.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
            code = int(st[1])
            rh = _parse_head(b"X / X\r\n" + raw.split(b"\r\n", 1)[1])
            rhdr = rh[3] if rh else []
            ct = _get(rhdr, "content-type").lower()
            if code not in (200, 206) or "mpegurl" in ct or _get(rhdr, "location"):
                try:
                    uw.close()                          # needs the careful path (fresh link, other host, playlist)
                except Exception:
                    pass
                return None
            return ur, uw, st, rhdr
        except Exception as ex:
            if uw is not None:
                try:
                    uw.close()
                except Exception:
                    pass
            if attempt == 0 and was_reused:
                continue                                # a pooled connection had gone stale: once more with a fresh one
            print("[relay] pipe open failed (%s %s): %s" % (csp.scheme, worker._host(csp.geturl()), repr(ex)[:100]), flush=True)
            return None
    return None


async def _handle_p(reader, writer, method, target, hdr, peer):
    origin = _get(hdr, "origin")
    if method == "OPTIONS":
        req_h = _get(hdr, "access-control-request-headers", "*")
        await _send_simple(writer, 204, "", origin, "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\nAccess-Control-Allow-Headers: %s\r\nAccess-Control-Max-Age: 600\r\n" % req_h)
        return
    if method not in ("GET", "HEAD"):
        await _send_simple(writer, 403, "forbidden", origin)
        return
    qs = parse_qs(urlsplit(target).query, keep_blank_values=True)
    e = (qs.get("e") or [""])[0]
    t = (qs.get("t") or [""])[0]
    q = (qs.get("q") or [""])[0]
    u = core.dec(e) if e else ""
    if not u:
        return await _send_simple(writer, 403, "forbidden", origin)
    spec = None
    if u.startswith("mb:"):
        try:
            spec = json.loads(u[3:])
            assert isinstance(spec, dict)
        except Exception:
            return await _send_simple(writer, 403, "forbidden", origin)
    elif not core.safe_url(u):
        return await _send_simple(writer, 403, "forbidden", origin)
    p, why = core.check(u, t, _client_ip(hdr, peer), _get(hdr, "x-device"), worker.CHECK_IP)
    if not p:
        print("[relay] refused:", why, flush=True)
        return await _send_simple(writer, 403, "forbidden", origin)
    ref = (core.dec(q) if q else "") or worker.DEFAULT_REFERER
    if not ref.lower().startswith(("http://", "https://")):
        ref = worker.DEFAULT_REFERER
    if spec is not None:
        u, ref_mb = await worker.resolve(spec)
        if not u:
            return await _send_simple(writer, 502, "no stream", origin)
        ref = ref_mb or ref
        if not core.safe_url(u):
            return await _send_simple(writer, 403, "forbidden", origin)
    rng = _get(hdr, "range") or None
    is_head = method == "HEAD"

    # ---- the pipe -------------------------------------------------------------------------
    sp = urlsplit(u)
    path_l = sp.path.lower()
    simple = (".m3u8" not in path_l) and sp.scheme in ("http", "https") and not worker._HOSTMAP.get(sp.hostname or "")
    ur = uw = None
    reusable = False
    if simple:
        host = sp.hostname or ""
        cands, mode = [], "https"
        if HTTP_FIRST and sp.scheme == "https":
            mode = _http_mode(host)                     # 'test' | 'http' | 'https'  (remembered for HTTP_TTL)
            if mode != "https":
                cands.append(_to_http(sp))
        cands.append(sp)
        simple = False
        for csp in cands:
            res = await _open_pipe(csp, method, ref, rng)
            if csp is not sp and mode == "test":        # a fresh test of this host: remember the result
                _HTTP_MEM[host] = (res is not None, time.time())
                print("[relay] http test %s: %s (remembered %dh)" % (host, "WORKS - no TLS decrypt" if res else "refused - https", HTTP_TTL // 3600), flush=True)
            if res is not None:
                ur, uw, st, rhdr = res
                sp = csp
                simple = True
                if csp.scheme == "http" and u.lower().startswith("https"):
                    STATS["http"] += 1
                break
    if simple:
        STATS["raw"] += 1
        keep = [(k, v) for k, v in rhdr if k.lower() in ("content-type", "content-length", "content-range", "accept-ranges", "transfer-encoding")]
        head = "HTTP/1.1 %s %s\r\n" % (st[1], st[2] if len(st) > 2 else "OK")
        head += "".join("%s: %s\r\n" % kv for kv in keep)
        head += "Cache-Control: private, max-age=1800\r\n" + _cors(origin)
        head += "Access-Control-Expose-Headers: %s\r\nConnection: close\r\n\r\n" % _CORS_EXPOSE
        writer.write(head.encode("latin-1"))
        clen = _get(rhdr, "content-length")
        reusable = (clen.isdigit() and not is_head and not _get(rhdr, "transfer-encoding")
                    and "close" not in _get(rhdr, "connection").lower())
        done = False
        try:
            if not is_head:
                remaining = int(clen) if reusable else None
                while remaining is None or remaining > 0:
                    d = await ur.read(CHUNK if remaining is None else min(CHUNK, remaining))
                    if not d:
                        break
                    writer.write(d)
                    STATS["bytes"] += len(d)
                    if remaining is not None:
                        remaining -= len(d)
                    await writer.drain()
                done = remaining == 0
            else:
                await writer.drain()
        finally:
            if reusable and done:
                _release(sp, ur, uw)                  # keep the TLS connection for the next request
            else:
                try:
                    uw.close()
                except Exception:
                    pass
        return
    if uw is not None:
        try:
            uw.close()
        except Exception:
            pass
    # ---- careful path -------------------------------------------------------------------------
    try:
        r, u2, is_pl = await _fallback(writer, u, ref, rng, spec, is_head, origin)
    except Exception as ex:
        print("[relay] upstream failed:", repr(ex)[:160], flush=True)
        return await _send_simple(writer, 502, "bad gateway", origin)
    if is_pl:
        await _playlist(writer, r, u2, p, q, t, origin)


async def handle(reader, writer, internal_port):
    try:
        peer = (writer.get_extra_info("peername") or ("",))[0]
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except Exception:
            return
        parsed = _parse_head(head[:-4])
        if not parsed:
            return await _send_simple(writer, 400, "bad request")
        method, target, _, hdr = parsed
        if target.split("?", 1)[0] == "/p":
            await _handle_p(reader, writer, method, target, hdr, peer)
        else:
            await _splice(reader, writer, head[:-4], hdr, internal_port)
    except (ConnectionError, asyncio.CancelledError, asyncio.IncompleteReadError):
        pass
    except Exception as ex:
        print("[relay] pipe error:", repr(ex)[:160], flush=True)
    finally:
        try:
            writer.close()
        except Exception:
            pass
