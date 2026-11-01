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

Every /p and /pt request writes ONE trace block to the log (rtrace.py): every step, its wall time and (where it
can be measured) its real CPU.  RELAY_LOG=0 switches the blocks off.  The 10 second [cpu] line stays.
"""
import asyncio
import json
import os
import ssl
import time
from urllib.parse import parse_qs, quote, urlsplit

import fcntl
import rtrace
import tlspass
import worker
import worker_core as core

CHUNK = worker.CHUNK
HEAD_LIMIT = 32768
VERIFY_TLS = os.getenv("RAW_VERIFY_TLS", "1") != "0"
_ctx = ssl.create_default_context()
if not VERIFY_TLS:
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE
STATS = {"raw": 0, "fallback": 0, "pass": 0, "bytes": 0, "new_conn": 0, "reused": 0, "http": 0, "tls": 0, "splice": 0}

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


async def _acquire(sp, fresh=False, tr=rtrace.NULL):
    """-> (reader, writer, reused)"""
    key = _pool_key(sp)
    lst = _POOL.get(key) or []
    dropped = 0
    while lst and not fresh:
        r, w, t = lst.pop()
        if time.time() - t < POOL_TTL and not w.is_closing() and not r.at_eof():
            STATS["reused"] += 1
            tr.lap("take an idle CDN connection from the pool", "%s://%s reused (idle %.1fs, %d stale dropped, %d left in pool)" % (
                sp.scheme, sp.hostname, time.time() - t, dropped, len(lst)))
            return r, w, True
        dropped += 1
        try:
            w.close()
        except Exception:
            pass
    port = key[2]
    r, w = await asyncio.wait_for(asyncio.open_connection(
        sp.hostname, port, ssl=_ctx if sp.scheme == "https" else None,
        server_hostname=sp.hostname if sp.scheme == "https" else None, limit=CHUNK * 2), 10)
    STATS["new_conn"] += 1
    tr.lap("open a NEW connection to the CDN", "%s://%s:%d (%s; DNS + TCP%s all inside asyncio, so no separate cpu number)%s" % (
        sp.scheme, sp.hostname, port, "fresh requested" if fresh else "pool empty or stale", " + TLS handshake + certificate check %s" % ("ON" if VERIFY_TLS else "OFF") if sp.scheme == "https" else "",
        (", %d stale dropped" % dropped) if dropped else ""))
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
    tlast = dict(tlspass.STATS)
    t0, c0 = time.time(), time.process_time()
    while True:
        await asyncio.sleep(10)
        now, cn = time.time(), time.process_time()
        d = {k: STATS[k] - last.get(k, 0) for k in STATS}
        last = dict(STATS)
        td = {k: tlspass.STATS[k] - tlast.get(k, 0) for k in tlspass.STATS}
        tlast = dict(tlspass.STATS)
        if d["raw"] or d["fallback"] or d["pass"] or d["tls"]:
            mb = d["bytes"] / 1048576.0
            cpu = (cn - c0) / max(0.001, now - t0) * 100
            print("[cpu] %ds: cpu=%d%% requests=%d (pipe=%d careful=%d app=%d) data=%.1fMB (%.2f cpu-sec/MB) new_tls=%d reused=%d http_pipe=%d tls_pass=%d splice=%d" % (
                now - t0, cpu, d["raw"] + d["fallback"] + d["pass"] + d["tls"], d["raw"], d["fallback"], d["pass"], mb,
                ((cn - c0) / mb) if mb else 0, d["new_conn"], d["reused"], d["http"], d["tls"], d["splice"]), flush=True)
            nh = td["full"] + td["resumed"]
            if nh or td["fail"]:
                print("[cpu]   pass-through handshakes: full=%d resumed=%d failed=%d | handshake cpu total=%.0fms avg=%.1fms | pass-through setup (dns..head) avg wall=%.0fms" % (
                    td["full"], td["resumed"], td["fail"], td["hs_cpu_ms"], td["hs_cpu_ms"] / max(1, nh), td["hs_wall_ms"] / max(1, td["ok"])), flush=True)
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


async def _fallback(writer, u, ref, rng, spec, is_head, origin, tr=rtrace.NULL):
    """the normal (httpx) path: redirects, fresh links, other CDN hosts, playlists"""
    STATS["fallback"] += 1
    tr.note("normal path (httpx via worker.py): redirects / fresh link / other CDN host / playlist / error answers")
    r, u2 = await worker._open(u, ref, rng, spec)
    ct = r.headers.get("content-type", "").lower()
    tr.status = r.status_code
    tr.lap("open the CDN with the normal path (worker._open)", "status %s, content-type %s, final url host %s (httpx does DNS + TLS + redirects inside, no separate cpu number)" % (
        r.status_code, ct or "-", worker._host(u2)))
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
            n = reads = 0
            cpu = 0.0
            async for chunk in r.aiter_raw(CHUNK):
                p = time.process_time()
                writer.write(chunk)
                n += len(chunk)
                reads += 1
                STATS["bytes"] += len(chunk)
                cpu += time.process_time() - p
                await writer.drain()
            tr.cpu(cpu)
            tr.bytes += n
            tr.lap("copy the body to the phone (python + httpx)", "%d chunk(s), %.1fKB each on average; cpu is only the write part, httpx's own read/decrypt cpu is not in this number" % (reads, n / 1024.0 / max(1, reads)))
        else:
            await writer.drain()
            tr.lap("send head only (HEAD request)")
    finally:
        if not (r.status_code == 200 and ("mpegurl" in ct or u2.split("?")[0].lower().endswith(".m3u8"))):
            await r.aclose()
    return None, u2, False


async def _playlist(writer, r, u2, p, q, t, origin, tr=rtrace.NULL):
    """playlists are small text files: rewritten by the normal code"""
    ck = (u2, t, q)
    hit = worker._PLCACHE.get(ck)
    if hit and time.time() - hit[0] < 120:
        body = hit[1]
        await r.aclose()
        tr.lap("playlist: taken from the cache", "%dB" % len(body))
    else:
        try:
            text = (await r.aread()).decode("utf-8", "ignore")
        finally:
            await r.aclose()
        tr.lap("playlist: download from the CDN", "%dB" % len(text))
        with tr.blk():
            body = core.rewrite_m3u8(text, str(r.url), p, q)
            worker._PLCACHE[ck] = (time.time(), body)
        tr.lap("playlist: rewrite every link and sign it", "%d lines" % (text.count("\n") + 1))
    b = body.encode()
    head = ("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nContent-Length: %d\r\nCache-Control: no-store\r\n%s"
            "Access-Control-Expose-Headers: %s\r\nConnection: close\r\n\r\n" % (len(b), _cors(origin), _CORS_EXPOSE)).encode()
    writer.write(head + b)
    await writer.drain()
    tr.bytes += len(b)
    tr.lap("send playlist to the phone", "%dB" % len(b))


async def _open_pipe(csp, method, ref, rng, why=None, tr=rtrace.NULL):
    """open (or reuse) a connection to the CDN for csp, send the head, read the answer head.
    -> (reader, writer, status_parts, response_headers) when the answer is a plain 200/206 body the pipe can copy,
       None otherwise (error, 4xx/5xx, redirect, playlist). A connection that is not usable is closed here."""
    was_reused = False
    for attempt in (0, 1):
        ur = uw = None
        was_reused = False
        try:
            if attempt:
                tr.note("the pooled connection was dead: trying once more with a fresh one")
            ur, uw, was_reused = await _acquire(csp, fresh=bool(attempt), tr=tr)
            with tr.blk():
                rq = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferer: %s\r\nOrigin: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n" % (
                    method, (csp.path or "/") + (("?" + csp.query) if csp.query else ""), csp.netloc, worker.UA, ref, ref.rstrip("/"))
                if rng:
                    rq += "Range: %s\r\n" % rng
                uw.write((rq + "Connection: keep-alive\r\n\r\n").encode("latin-1"))
            tr.lap("send the request to the CDN (%s)" % csp.scheme, "Referer %s, Range %s%s" % (ref, rng or "-", "; TLS encrypt happens here for https" if csp.scheme == "https" else ""))
            raw = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), 20)
            tr.lap("wait for the CDN answer head", "%dB; CDN thinking + network time" % len(raw) + ("; for https the TLS decrypt of these bytes is included but cannot be separated" if csp.scheme == "https" else ""))
            with tr.blk():
                st = raw.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
                code = int(st[1])
                rh = _parse_head(b"X / X\r\n" + raw.split(b"\r\n", 1)[1])
                rhdr = rh[3] if rh else []
                ct = _get(rhdr, "content-type").lower()
            tr.lap("parse the answer head", "status %d, content-type %s, content-length %s" % (code, ct or "-", _get(rhdr, "content-length") or "-"))
            if code not in (200, 206) or "mpegurl" in ct or _get(rhdr, "location"):
                if why is not None:
                    why.append("status %d%s%s" % (code, (" -> " + _get(rhdr, "location")[:80]) if _get(rhdr, "location") else "",
                                                  " (playlist)" if "mpegurl" in ct else ""))
                tr.note("this answer cannot be piped (status %d%s%s): closing, the careful path will handle it" % (
                    code, " redirect" if _get(rhdr, "location") else "", " playlist" if "mpegurl" in ct else ""))
                try:
                    uw.close()                          # needs the careful path (fresh link, other host, playlist)
                except Exception:
                    pass
                return None
            return ur, uw, st, rhdr
        except Exception as ex:
            tr.lap("FAILED to open the pipe", repr(ex)[:140])
            if uw is not None:
                try:
                    uw.close()
                except Exception:
                    pass
            if attempt == 0 and was_reused:
                continue                                # a pooled connection had gone stale: once more with a fresh one
            if why is not None:
                why.append(repr(ex)[:100])
            print("[relay] pipe open failed (%s %s): %s" % (csp.scheme, worker._host(csp.geturl()), repr(ex)[:100]), flush=True)
            return None
    return None


SPLICE = os.getenv("SPLICE", "1") != "0"      # bytes go CDN socket -> pipe -> phone socket inside the kernel (python never touches them)
_SPLICE_OK = [hasattr(os, "splice")]
_F_SETPIPE_SZ = 1031


async def _wait_fd(loop, fd, write, idle):
    fut = loop.create_future()
    (loop.add_writer if write else loop.add_reader)(fd, lambda: fut.done() or fut.set_result(True))
    h = loop.call_later(idle, lambda: fut.done() or fut.set_result(False))
    try:
        return await fut
    finally:
        h.cancel()
        (loop.remove_writer if write else loop.remove_reader)(fd)


async def _splice_pump(ur, uw, writer, idle=30, tr=rtrace.NULL, reason=None):
    """Move the rest of the CDN answer to the phone without python touching the bytes.
    -> number of bytes moved, or None when it could not be set up (nothing was moved: the caller uses the normal loop).
    reason (list): why it was not used.  tr: every step is written to the trace."""
    if reason is None:
        reason = []
    try:
        if not SPLICE:
            reason.append("SPLICE=0 in the settings")
            return None
        if not _SPLICE_OK[0]:
            reason.append("os.splice is missing or was switched off after a failure")
            return None
        if ur.at_eof():
            reason.append("the CDN had already closed the connection")
            return None
        if writer.get_extra_info("ssl_object") is not None or uw.get_extra_info("ssl_object") is not None:
            reason.append("a socket is TLS inside python (splice needs plain sockets)")
            return None
        tr_, utr = writer.transport, uw.transport
        with tr.blk():
            buf = bytes(ur._buffer)                 # bytes python already read from the CDN socket
            ur._buffer.clear()
            if buf:
                writer.write(buf)
        await writer.drain()                    # nothing may wait in python's write buffer: from here the kernel writes to the socket
        tr.bytes += len(buf)
        tr.lap("splice 1: send what python had already read", "%dB were in python's read buffer" % len(buf))
        if tr_.get_write_buffer_size():
            reason.append("python's write buffer to the phone was not empty")
            return None
        loop = asyncio.get_running_loop()
        with tr.blk():
            sfd = os.dup(uw.get_extra_info("socket").fileno())      # a copy of the fd: asyncio does not let two readers wait on its own fd
            cfd = None
            try:
                cfd = os.dup(writer.get_extra_info("socket").fileno())
                rp, wp = os.pipe()
            except Exception as ex:
                os.close(sfd)
                if cfd is not None:
                    os.close(cfd)
                reason.append("dup/pipe failed: " + repr(ex)[:60])
                sfd = None
        if sfd is None:
            tr.lap("splice 2: copy the sockets + make the pipe", "FAILED")
            return None
    except Exception as ex:
        reason.append("setup error: " + repr(ex)[:80])
        return None
    moved = len(buf)
    n_in = n_out = w_in = w_out = 0
    cpu = 0.0
    ended = "?"
    try:
        with tr.blk():
            try:
                fcntl.fcntl(wp, _F_SETPIPE_SZ, 1 << 20)
                psz = "pipe size set to 1 MB"
            except OSError as ex:
                psz = "pipe size NOT changed (%s)" % repr(ex)[:40]
            os.set_blocking(rp, False)
            os.set_blocking(wp, False)
            utr.pause_reading()
            tr_.pause_reading()
        tr.lap("splice 2: copy the sockets + make the pipe", "%s; python stops reading both sockets from now on" % psz)
        first = True
        while True:
            p = time.process_time()
            try:
                n = os.splice(sfd, wp, 1 << 20)
                cpu += time.process_time() - p
                n_in += 1
            except BlockingIOError:
                cpu += time.process_time() - p
                w_in += 1
                if not await _wait_fd(loop, sfd, False, idle):
                    if first and moved == len(buf):
                        _SPLICE_OK[0] = False           # nothing ever arrived this way: do not use it again
                        print("[relay] splice: no data, switching it off", flush=True)
                        ended = "no data ever arrived through splice - switched OFF"
                    else:
                        ended = "the CDN went quiet for %ds" % idle
                    break                               # the CDN went quiet
                continue
            first = False
            if n == 0:
                ended = "the CDN closed the connection (normal end)"
                break                                   # the CDN closed: done
            moved += n
            while n > 0:
                p = time.process_time()
                try:
                    m = os.splice(rp, cfd, n)
                    cpu += time.process_time() - p
                    n_out += 1
                except BlockingIOError:
                    cpu += time.process_time() - p
                    w_out += 1
                    if not await _wait_fd(loop, cfd, True, idle):
                        ended = "the phone did not take data for %ds" % idle
                        return moved
                    continue
                n -= m
    except Exception as ex:
        ended = "stopped: %s (phone hung up or CDN reset)" % repr(ex)[:60]
    finally:
        for f in (sfd, cfd, rp, wp):
            try:
                os.close(f)
            except OSError:
                pass
        tr.cpu(cpu)
        calls = n_in + n_out + w_in + w_out
        tr.bytes += moved - len(buf)
        tr.lap("splice 3: copy CDN -> phone inside the kernel",
               "%.2fMB moved; os.splice calls: %d in + %d out; waits for CDN data: %d, for the phone socket: %d; cpu in the syscalls %.1fms (%.3fms per call); ended: %s" % (
                   (moved - len(buf)) / 1048576.0, n_in, n_out, w_in, w_out, cpu * 1000.0, cpu * 1000.0 / max(1, calls), ended))
    return moved


_PASS_BAD = {}          # host -> time: the CDN could not do TLS 1.2 + AES-GCM (or the handshake failed); do not try again for a while
PASS_BAD_TTL = int(os.getenv("PASS_BAD_TTL", "1800"))


async def _try_pass(csp, ref, rng, writer, origin, tr=rtrace.NULL, phone_keys=False):
    """TLS pass-through (see tlspass.py): True = the whole answer was sent (locked bytes + key material for the phone), False = use the normal path"""
    host = csp.hostname or ""
    bad_for = time.time() - _PASS_BAD.get(host, 0)
    if bad_for < PASS_BAD_TTL:
        tr.note("pass-through skipped: it failed for %s %.0fs ago (retry after %ds)" % (host, bad_for, PASS_BAD_TTL))
        return False
    why = []
    port = csp.port or 443
    with tr.blk():
        hd = "Host: %s\r\nUser-Agent: %s\r\nReferer: %s\r\nOrigin: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n" % (
            csp.netloc, worker.UA, ref, ref.rstrip("/"))
        if rng:
            hd += "Range: %s\r\n" % rng
        hd += "Connection: close"
    tr.note("pass-through: phone works out the key itself" if phone_keys else "pass-through: old phone (no k=1), the relay works out the key")
    res = await tlspass.open_pass(host, port, (csp.path or "/") + (("?" + csp.query) if csp.query else ""), hd, why, tr, phone_keys)
    if res is None:
        _PASS_BAD[host] = time.time()
        tr.note("pass-through NOT possible: %s" % ("; ".join(why) or "?"))
        print("[relay] tls pass-through %s: not possible (%s) - normal https for %dmin" % (host, "; ".join(why) or "?", PASS_BAD_TTL // 60), flush=True)
        return False
    rhdr = res["hdr"]
    ct = _get(rhdr, "content-type").lower()
    tr.status = res["status"]
    if res["status"] not in (200, 206) or "mpegurl" in ct or _get(rhdr, "location"):
        tr.note("CDN answer is %d%s%s: not a plain video body, closing and using the careful path" % (
            res["status"], (" -> " + _get(rhdr, "location")[:80]) if _get(rhdr, "location") else "", " (playlist)" if "mpegurl" in ct else ""))
        print("[relay] tls pass-through %s: answer is %d%s - careful path" % (host, res["status"], (" -> " + _get(rhdr, "location")[:80]) if _get(rhdr, "location") else ""), flush=True)
        res["writer"].close()
        return False
    if _HTTP_LOG.get(("pass", host), 0) + 600 < time.time():
        _HTTP_LOG[("pass", host)] = time.time()
        print("[relay] tls pass-through %s: WORKS (%s) - no decrypt here, the phone opens it" % (host, res["name"]), flush=True)
    STATS["tls"] += 1
    with tr.blk():
        if phone_keys:
            keyh = "X-Tls2: %s.%s.%s.%d.%d.%d\r\n" % (res["ms"], res["cr"], res["sr"], res["h"], res["klen"], res["q"])
        else:
            keyh = "X-Tls: %s.%s.%d\r\n" % (res["k"], res["s"], res["q"])
        head = ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n%sCache-Control: no-store\r\n%s"
                "Access-Control-Expose-Headers: X-Tls, X-Tls2\r\nConnection: close\r\n\r\n" % (keyh, _cors(origin))).encode("latin-1")
        blob = head + b"".join(res["raws"])
    ur, uw = res["reader"], res["writer"]
    loop = asyncio.get_running_loop()
    tr_ = writer.transport
    last = [loop.time()]
    wd = [None]

    def watch():                                # one timer for the whole copy (a wait_for per chunk costs a task each time)
        if loop.time() - last[0] > 30:
            uw.close()                          # CDN went quiet: the read below ends
        else:
            wd[0] = loop.call_later(10, watch)

    try:
        writer.write(blob)
        STATS["bytes"] += len(blob) - len(head)
        await writer.drain()
        tr.bytes += len(blob) - len(head)
        tr.lap("send answer head + the still-locked bytes to the phone", "%dB = head %dB (%s) + %dB locked bytes the relay had already read" % (
            len(blob), len(head), "X-Tls2: key material for the phone" if phone_keys else "X-Tls: finished key", len(blob) - len(head)))
        sreason = []
        moved = await _splice_pump(ur, uw, writer, tr=tr, reason=sreason)
        if moved is not None:
            STATS["splice"] += 1
            STATS["bytes"] += moved
            return True
        tr.note("splice NOT used (%s): using the python copy loop" % ("; ".join(sreason) or "?"))
        wd[0] = loop.call_later(10, watch)
        n = reads = drains = 0
        cpu = 0.0
        ended = "the CDN closed the connection (normal end)"
        while True:
            d = await ur.read(CHUNK)
            if not d:
                break
            if tr_.is_closing():
                ended = "the phone hung up"
                break
            p = time.process_time()
            last[0] = loop.time()
            writer.write(d)
            n += len(d)
            reads += 1
            big = tr_.get_write_buffer_size() > 524288
            cpu += time.process_time() - p
            if big:                                     # wait for the phone only when it really is behind
                drains += 1
                await writer.drain()
        STATS["bytes"] += n
        tr.cpu(cpu)
        tr.bytes += n
        tr.lap("python copy loop CDN -> phone", "%.2fMB, %d reads (%.0fKB each on average), %d waits for the phone; cpu only counts the write part; ended: %s" % (
            n / 1048576.0, reads, n / 1024.0 / max(1, reads), drains, ended))
    except Exception as ex:
        tr.note("copy stopped: %s (the phone has what it needs and hung up, or the CDN went quiet)" % repr(ex)[:80])
    finally:
        if wd[0] is not None:
            wd[0].cancel()
        try:
            uw.close()
        except Exception:
            pass
    return True


_HTTP_LOG = {}


async def _handle_p(reader, writer, method, target, hdr, peer, pt=False, tr=rtrace.NULL):
    origin = _get(hdr, "origin")
    tr.kv["phone"] = peer
    if method == "OPTIONS":
        req_h = _get(hdr, "access-control-request-headers", "*")
        await _send_simple(writer, 204, "", origin, "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\nAccess-Control-Allow-Headers: %s\r\nAccess-Control-Max-Age: 600\r\n" % req_h)
        tr.status = 204
        tr.lap("answer the CORS pre-flight (OPTIONS)")
        return
    if method not in ("GET", "HEAD"):
        await _send_simple(writer, 403, "forbidden", origin)
        tr.status = 403
        tr.lap("refuse: method %s" % method)
        return
    with tr.blk():
        qs = parse_qs(urlsplit(target).query, keep_blank_values=True)
        e = (qs.get("e") or [""])[0]
        t = (qs.get("t") or [""])[0]
        q = (qs.get("q") or [""])[0]
        phone_keys = pt and (qs.get("k") or [""])[0] == "1"       # the new sw.js asks for  &k=1  = "I work out the key myself"
        u = core.dec(e) if e else ""
    tr.lap("read the link parameters + decrypt the url", "e=%dB t=%dB, phone works out key: %s" % (len(e), len(t), "yes" if phone_keys else "no"))
    if not u:
        tr.status = 403
        tr.lap("refuse: link could not be decrypted")
        return await _send_simple(writer, 403, "forbidden", origin)
    spec = None
    if u.startswith("mb:"):
        try:
            spec = json.loads(u[3:])
            assert isinstance(spec, dict)
        except Exception:
            tr.status = 403
            tr.lap("refuse: bad movie link")
            return await _send_simple(writer, 403, "forbidden", origin)
    elif not core.safe_url(u):
        tr.status = 403
        tr.lap("refuse: url is not allowed")
        return await _send_simple(writer, 403, "forbidden", origin)
    with tr.blk():
        p, why = core.check(u, t, _client_ip(hdr, peer), _get(hdr, "x-device"), worker.CHECK_IP)
    tr.lap("check the link signature, expiry, device", "ok" if p else "REFUSED: %s" % why)
    if not p:
        print("[relay] refused:", why, flush=True)
        tr.status = 403
        return await _send_simple(writer, 403, "forbidden", origin)
    ref = (core.dec(q) if q else "") or worker.DEFAULT_REFERER
    if not ref.lower().startswith(("http://", "https://")):
        ref = worker.DEFAULT_REFERER
    if spec is not None:
        u, ref_mb = await worker.resolve(spec)
        tr.lap("resolve the movie link (worker.resolve)", "%s (a cached answer is fast, a new one asks MovieBox)" % ("ok " + worker._host(u) if u else "NO STREAM"))
        if not u:
            tr.status = 502
            return await _send_simple(writer, 502, "no stream", origin)
        ref = ref_mb or ref
        if not core.safe_url(u):
            tr.status = 403
            return await _send_simple(writer, 403, "forbidden", origin)
    rng = _get(hdr, "range") or None
    is_head = method == "HEAD"
    tr.kv["host"] = worker._host(u)
    tr.kv["range"] = rng or "-"

    # ---- the pipe -------------------------------------------------------------------------
    with tr.blk():
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
        tr.lap("choose the way to the CDN", "%s: plain pipe possible; http-first memory for this host: %s; will try: %s" % (
            "/pt" if pt else "/p", mode, " then ".join(c.scheme for c in cands) + (" (pass-through on https)" if pt and not is_head else "")))
        simple = False
        for csp in cands:
            if pt and csp.scheme == "https" and not is_head:
                if await _try_pass(csp, ref, rng, writer, origin, tr, phone_keys):
                    return                              # sent: locked bytes + key, the phone opens them
            rwhy = []
            res = await _open_pipe(csp, method, ref, rng, rwhy, tr)
            if csp is not sp and mode == "test":        # a fresh test of this host: remember the result
                _HTTP_MEM[host] = (res is not None, time.time())
                tr.note("http test result remembered: %s" % ("WORKS" if res else "refused: " + ("; ".join(rwhy) or "?")))
                print("[relay] http test %s: %s (remembered %dh)" % (host, "WORKS - no TLS decrypt" if res else "refused - https; reason: " + ("; ".join(rwhy) or "?"), HTTP_TTL // 3600), flush=True)
            if res is not None:
                ur, uw, st, rhdr = res
                sp = csp
                simple = True
                if csp.scheme == "http" and u.lower().startswith("https"):
                    STATS["http"] += 1
                break
    else:
        tr.lap("choose the way to the CDN", "careful path only (playlist, special host map, or not http/https)")
    if simple:
        STATS["raw"] += 1
        tr.status = st[1]
        tr.note("plain pipe over %s: the relay copies the bytes with read()/write()%s" % (sp.scheme, " and DECRYPTS them here (https)" if sp.scheme == "https" else " (http: nothing to decrypt)"))
        with tr.blk():
            keep = [(k, v) for k, v in rhdr if k.lower() in ("content-type", "content-length", "content-range", "accept-ranges", "transfer-encoding")]
            head = "HTTP/1.1 %s %s\r\n" % (st[1], st[2] if len(st) > 2 else "OK")
            head += "".join("%s: %s\r\n" % kv for kv in keep)
            head += "Cache-Control: private, max-age=1800\r\n" + _cors(origin)
            head += "Access-Control-Expose-Headers: %s\r\nConnection: close\r\n\r\n" % _CORS_EXPOSE
            writer.write(head.encode("latin-1"))
            clen = _get(rhdr, "content-length")
            reusable = (clen.isdigit() and not is_head and not _get(rhdr, "transfer-encoding")
                        and "close" not in _get(rhdr, "connection").lower())
        tr.lap("build + queue the answer head for the phone", "%dB" % len(head))
        done = False
        n = reads = drains = 0
        cpu = 0.0
        try:
            if not is_head:
                remaining = int(clen) if reusable else None
                while remaining is None or remaining > 0:
                    d = await ur.read(CHUNK if remaining is None else min(CHUNK, remaining))
                    if not d:
                        break
                    p_ = time.process_time()
                    writer.write(d)
                    STATS["bytes"] += len(d)
                    n += len(d)
                    reads += 1
                    if remaining is not None:
                        remaining -= len(d)
                    cpu += time.process_time() - p_
                    drains += 1
                    await writer.drain()
                done = remaining == 0
                tr.cpu(cpu)
                tr.bytes += n
                tr.lap("python copy loop CDN -> phone (%s)" % sp.scheme,
                       "%.2fMB, %d reads (%.0fKB each), cpu only counts the write part%s; finished cleanly: %s" % (
                           n / 1048576.0, reads, n / 1024.0 / max(1, reads),
                           " - the TLS decrypt of every read is NOT in this cpu number (it is inside ur.read), see whole-process cpu" if sp.scheme == "https" else "", done))
            else:
                await writer.drain()
                tr.lap("send head only (HEAD request)")
        finally:
            if reusable and done:
                _release(sp, ur, uw)                  # keep the TLS connection for the next request
                tr.note("CDN connection put back in the pool for the next request")
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
        r, u2, is_pl = await _fallback(writer, u, ref, rng, spec, is_head, origin, tr)
    except Exception as ex:
        print("[relay] upstream failed:", repr(ex)[:160], flush=True)
        tr.status = 502
        tr.lap("careful path FAILED", repr(ex)[:140])
        return await _send_simple(writer, 502, "bad gateway", origin)
    if is_pl:
        await _playlist(writer, r, u2, p, q, t, origin, tr)


async def handle(reader, writer, internal_port):
    t0, p0 = time.perf_counter(), time.process_time()           # when this connection started (for the trace)
    tr = rtrace.NULL
    try:
        peer = (writer.get_extra_info("peername") or ("",))[0]
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except Exception:
            return
        pc = time.process_time()
        parsed = _parse_head(head[:-4])
        if not parsed:
            return await _send_simple(writer, 400, "bad request")
        method, target, _, hdr = parsed
        tp = target.split("?", 1)[0]
        if tp == "/p" or tp == "/pt":
            tr = rtrace.new(("pt " if tp == "/pt" else "p ") + method, t0, p0)
            tr.cpu(time.process_time() - pc)
            tr.lap("read + parse the request head from the phone", "%dB; the wall time mostly is waiting for the phone / the network" % len(head))
            await _handle_p(reader, writer, method, target, hdr, peer, tp == "/pt", tr)
        else:
            await _splice(reader, writer, head[:-4], hdr, internal_port)
    except (ConnectionError, asyncio.CancelledError, asyncio.IncompleteReadError) as ex:
        tr.note("connection ended: %s" % type(ex).__name__)
    except Exception as ex:
        tr.note("ERROR: %s" % repr(ex)[:160])
        print("[relay] pipe error:", repr(ex)[:160], flush=True)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        tr.end("close the connection to the phone")
