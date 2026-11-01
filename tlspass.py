"""TLS pass-through: the relay does NOT decrypt the video, the phone does.

Normal https relay:   CDN --(TLS)--> relay [decrypts every byte, ~0.05 cpu-sec/MB] --> phone
This module:          CDN --(TLS)--> relay [copies the locked bytes]               --> phone [decrypts, AES-GCM in hardware]

How it works (TLS 1.2, AES-GCM only):
  1. The relay does the TLS handshake with the CDN itself (python ssl + MemoryBIO), sends the request with the
     swapped Referer, and reads just enough of the answer to see the HTTP status line + headers.
  2. It then hands the phone what it needs to open the records of THIS connection:
       phone_keys=True  (new sw.js):  master secret + client random + server random + hash + key length.
                        The PHONE works out the key itself (tlsdec.js derive(), HMAC via WebCrypto).
       phone_keys=False (old sw.js): the relay works out the server write key + salt and sends only those (header X-Tls).
  3. From there on the relay only copies the raw encrypted TLS records from the CDN socket to the phone.
     The phone (sw.js + tlsdec.js, WebCrypto AES-GCM) decrypts them.

Anything that is not a plain 200/206 body (errors, redirects, playlists) or any problem (CDN has no TLS 1.2 /
no AES-GCM, no keylog) returns None, and the caller uses the normal path.

TLS_PASS=0 turns the whole thing off.
Every step of every request is written to the log by rtrace.py (RELAY_LOG=0 = off).
"""
import asyncio
import atexit
import hashlib
import hmac
import os
import socket
import ssl
import tempfile
import time

import rtrace

ENABLED = os.getenv("TLS_PASS", "1") != "0"
VERIFY_TLS = os.getenv("RAW_VERIFY_TLS", "1") != "0"
SESS_TTL = int(os.getenv("PASS_SESSION_TTL", "3600"))
STATS = {"ok": 0, "fail": 0, "resumed": 0, "full": 0, "hs_wall_ms": 0.0, "hs_cpu_ms": 0.0}
_DNS = {}               # (host, port) -> (addresses, time)
DNS_TTL = int(os.getenv("DNS_TTL", "600"))
_SESS = {}              # host -> (SSLSession, master_secret, time)
_PENDING = [0]          # handshakes in flight (the keylog file is only emptied when none is running)
KEYLOG = ""
_ctx = None


def _init():
    global KEYLOG, _ctx, ENABLED
    if not ENABLED:
        return
    try:
        for d in ("/dev/shm", tempfile.gettempdir()):
            if os.path.isdir(d) and os.access(d, os.W_OK):
                KEYLOG = os.path.join(d, ".jf-keylog-%d" % os.getpid())
                break
        fd = os.open(KEYLOG, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.close(fd)
        atexit.register(lambda: os.path.exists(KEYLOG) and os.remove(KEYLOG))
        c = ssl.create_default_context()
        if not VERIFY_TLS:
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        c.maximum_version = ssl.TLSVersion.TLSv1_2          # TLS 1.2 keeps the record format simple
        c.set_ciphers("ECDHE+AESGCM")                        # AES-GCM only: that is what WebCrypto in the browser can open
        c.keylog_filename = KEYLOG
        _ctx = c
        print("[relay] tls pass-through: certificate check %s (RAW_VERIFY_TLS=%s), keylog %s" % (
            "ON" if VERIFY_TLS else "OFF", os.getenv("RAW_VERIFY_TLS", "(not set -> 1)"), KEYLOG), flush=True)
    except Exception as ex:
        print("[relay] tls pass-through off (%s)" % repr(ex)[:120], flush=True)
        ENABLED = False


_init()


def _prf(secret, label, seed, n, h):
    seed = label + seed
    out, a = b"", seed
    while len(out) < n:
        a = hmac.new(secret, a, h).digest()
        out += hmac.new(secret, a + seed, h).digest()
    return out[:n]


def _master(cr, info=None):
    """master secret for this client_random from the keylog file (None if not there).
    info (dict, optional) gets: file size, bytes read, lines looked at, found"""
    want = b"CLIENT_RANDOM " + cr.hex().encode() + b" "
    try:
        with open(KEYLOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            data = f.read()
        lines = data.split(b"\n")
        n = 0
        for line in reversed(lines):
            n += 1
            if line.startswith(want):
                if info is not None:
                    info.update(size=size, read=len(data), lines=len(lines), looked=n, found=True)
                return bytes.fromhex(line[len(want):].strip().decode())
        if info is not None:
            info.update(size=size, read=len(data), lines=len(lines), looked=n, found=False)
    except Exception as ex:
        if info is not None:
            info["error"] = repr(ex)[:80]
    return None


def _trim_keylog():
    try:
        if not _PENDING[0] and os.path.getsize(KEYLOG) > 262144:
            os.truncate(KEYLOG, 0)
    except Exception:
        pass


async def _handshake(host, port, cached, tr):
    """-> (reader, writer, sslobj, in_bio, out_bio, client_random, server_random)
    Writes trace steps for: DNS, TCP connect, TLS handshake."""
    loop = asyncio.get_running_loop()
    # --- 1. DNS ---
    hit = _DNS.get((host, port))
    if hit and time.time() - hit[1] < DNS_TTL:
        addrs = list(hit[0])
        _DNS[(host, port)] = (hit[0][1:] + hit[0][:1], hit[1])     # rotate: spread over the CDN's addresses
    else:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), 10)
        addrs = []
        for _f, _t, _p, _c, sa in infos:
            if sa[0] not in addrs:
                addrs.append(sa[0])
        _DNS[(host, port)] = (addrs, time.time())
    tr.lap("DNS lookup of the CDN host", "%s -> %d address(es): %s (getaddrinfo runs in a helper thread)" % (host, len(addrs), ", ".join(addrs[:4])))
    # --- 2. TCP connect (the addresses in the order DNS gave them, like asyncio does) ---
    r = w = None
    last, failed, ip = None, [], ""
    for ip in addrs[:4]:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, limit=1 << 20), 6)
            break
        except Exception as ex:
            last = ex
            failed.append("%s: %s" % (ip, repr(ex)[:50]))
    if w is None:
        _DNS.pop((host, port), None)                 # stale addresses: look up again next time
        raise last or ConnectionError("no address")
    tr.lap("TCP connect to the CDN", "connected to %s:%d%s" % (ip, port, ("; failed before: " + " | ".join(failed)) if failed else ""))
    try:
        # --- 3. TLS handshake ---
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        hs_cpu = 0.0
        p = time.process_time()
        obj = _ctx.wrap_bio(inc, out, server_hostname=host, session=cached[0] if cached else None)
        hs_cpu += time.process_time() - p
        cr = sr = None
        got = bytearray()
        rounds = calls = sent = recvd = 0
        biggest = 0.0
        while True:
            p = time.process_time()
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            data = out.read()
            if data and cr is None and len(data) >= 44 and data[0] == 22 and data[5] == 1:
                cr = bytes(data[11:43])
            d = time.process_time() - p
            hs_cpu += d
            calls += 1
            biggest = max(biggest, d)
            if data:
                w.write(data)
                await w.drain()
                sent += len(data)
            if done:
                break
            chunk = await asyncio.wait_for(r.read(65536), 10)
            if not chunk:
                raise ConnectionError("closed during handshake")
            rounds += 1
            recvd += len(chunk)
            p = time.process_time()
            if sr is None:
                got += chunk
                if len(got) >= 44 and got[0] == 22 and got[5] == 2:
                    sr = bytes(got[11:43])
            inc.write(chunk)
            hs_cpu += time.process_time() - p
        if cr is None or sr is None:
            raise ValueError("no hello random")
        tr.cpu(hs_cpu)
        reused = bool(obj.session_reused)
        tr.lap("TLS handshake with the CDN",
               "%s | offered an old session: %s | %d round trip(s), %d do_handshake calls (biggest %.2fms), sent %dB, got %dB | cert check %s" % (
                   "RESUMED (short handshake)" if reused else "FULL handshake", "yes" if cached else "no", rounds, calls, biggest * 1000.0,
                   sent, recvd, "ON" if VERIFY_TLS else "OFF"))
        STATS["resumed" if reused else "full"] += 1
        STATS["hs_cpu_ms"] += hs_cpu * 1000.0
        return r, w, obj, inc, out, cr, sr
    except BaseException:
        try:
            w.close()
        except Exception:
            pass
        raise


async def open_pass(host, port, path_q, headers_text, why=None, tr=rtrace.NULL, phone_keys=False):
    """Do the TLS handshake, send the request, read the answer head.
    headers_text: the request head WITHOUT the request line and without the final blank line (Host, Referer, Range ...)
    phone_keys: True = give the phone the master secret + randoms (it works out the key), False = work out the key here
    -> dict(reader, writer, raws, status, hdr, name, q, + 'k','s' (old) or 'ms','cr','sr','h','klen' (phone_keys)) or None
    On success the first `raws` (bytes already read from the socket, still locked) MUST be sent to the phone first.
    Every step goes to tr (rtrace.Trace)."""
    if not ENABLED:
        tr.note("tls pass-through is switched off (TLS_PASS=0 or no keylog)")
        return None
    if why is None:
        why = []
    _PENDING[0] += 1
    w = None
    t_start = time.perf_counter()
    try:
        with tr.blk():
            cached = _SESS.get(host)
            age = (time.time() - cached[2]) if cached else 0
            if cached and age > SESS_TTL:
                cached = None
        tr.lap("look up an old TLS session for this host", ("found, %.0fs old" % age) if cached else "none (first request, or older than %ds)" % SESS_TTL)
        r, w, obj, inc, out, cr, sr = await _handshake(host, port, cached, tr)
        with tr.blk():
            cipher = obj.cipher()
            name = cipher[0]
        if cipher[1] != "TLSv1.2" or "GCM" not in name:
            why.append("cipher " + name)
            tr.lap("check cipher", "NOT usable: %s %s" % (cipher[1], name))
            return None
        tr.lap("check cipher", "%s %s, key %d bit" % (cipher[1], name, cipher[2]))
        # --- the key material ---
        minfo = {}
        with tr.blk():
            ms = _master(cr, minfo)
        src = "keylog file"
        if ms is None and obj.session_reused and cached:
            ms = cached[1]                                   # resumed: same master secret as the full handshake
            src = "kept from the full handshake (resumed session)"
        if ms is None:
            why.append("no keylog")
            tr.lap("read master secret from keylog", "NOT FOUND %r" % (minfo,))
            return None
        tr.lap("read master secret from keylog", "from %s; file %dB, read last %dB = %d lines, looked at %d lines, found=%s" % (
            src, minfo.get("size", 0), minfo.get("read", 0), minfo.get("lines", 0), minfo.get("looked", 0), minfo.get("found")))
        klen = cipher[2] // 8
        h = hashlib.sha384 if name.endswith("SHA384") else hashlib.sha256
        res = {"name": name, "q": 1}
        if phone_keys:
            res.update(ms=ms.hex(), cr=cr.hex(), sr=sr.hex(), h=384 if name.endswith("SHA384") else 256, klen=klen)
            tr.note("key expansion is done by the PHONE (it gets master secret + 2 randoms + hash %d + key length %d)" % (res["h"], klen))
        else:
            with tr.blk():
                kb = _prf(ms, b"key expansion", sr + cr, 2 * klen + 8, h)
                res["k"] = kb[klen:2 * klen].hex()
                res["s"] = kb[2 * klen + 4:2 * klen + 8].hex()
            tr.lap("work out the server write key (old way)", "key expansion done on the relay")
        with tr.blk():
            if not (obj.session_reused and cached):          # resumed: the stored session is still good, skip the copy
                if obj.session is not None:
                    _SESS[host] = (obj.session, ms, time.time())
        tr.lap("remember the TLS session for the next request")
        # --- request ---
        with tr.blk():
            obj.write(("GET %s HTTP/1.1\r\n%s\r\n" % (path_q, headers_text)).encode("latin-1") + b"\r\n")
            blob = out.read()
        w.write(blob)
        await w.drain()
        tr.lap("encrypt + send the request to the CDN", "%dB sent: GET %s ..." % (len(blob), path_q[:60]))
        # --- answer head (the locked bytes are kept so that the phone can decrypt them from the start) ---
        raws, plain = [], bytearray()
        nchunk = got_bytes = 0
        first = True
        while b"\r\n\r\n" not in plain:
            if len(plain) > 32768:
                why.append("head too big")
                tr.lap("read answer head", "head too big")
                return None
            chunk = await asyncio.wait_for(r.read(65536), 20)
            if not chunk:
                why.append("closed before head")
                tr.lap("read answer head", "CDN closed before the head")
                return None
            if first:
                first = False
                tr.lap("wait for the CDN's first answer bytes", "the CDN's own thinking + network time, not relay work")
            nchunk += 1
            got_bytes += len(chunk)
            with tr.blk():
                raws.append(chunk)
                inc.write(chunk)
                while True:
                    try:
                        d = obj.read(65536)
                    except ssl.SSLWantReadError:
                        break
                    if not d:
                        break
                    plain += d
        with tr.blk():
            head_b, _, rest_b = bytes(plain).partition(b"\r\n\r\n")
            head = head_b.decode("latin-1").split("\r\n")
            st = head[0].split(" ", 2)
            status = int(st[1])
            hdr = []
            for ln in head[1:]:
                k, _, v = ln.partition(":")
                hdr.append((k.strip(), v.strip()))
        tr.lap("decrypt + read the answer head here",
               "%d read(s), %dB from the socket; decrypted %dB (head %dB + %dB of video that came in the same read)" % (
                   nchunk, got_bytes, len(plain), len(head_b) + 4, len(rest_b)))
        res.update(reader=r, writer=w, raws=raws, status=status, hdr=hdr)
        w = None                                             # now owned by the caller
        STATS["ok"] += 1
        STATS["hs_wall_ms"] += (time.perf_counter() - t_start) * 1000.0
        return res
    except Exception as ex:
        STATS["fail"] += 1
        why.append(repr(ex)[:100])
        tr.lap("FAILED", repr(ex)[:160])
        return None
    finally:
        _PENDING[0] -= 1
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
        _trim_keylog()
