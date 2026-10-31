"""TLS pass-through: the relay does NOT decrypt the video, the phone does.

Normal https relay:   CDN --(TLS)--> relay [decrypts every byte, ~0.05 cpu-sec/MB] --> phone
This module:          CDN --(TLS)--> relay [copies the locked bytes]               --> phone [decrypts, AES-GCM in hardware]

How it works (TLS 1.2, AES-GCM only):
  1. The relay does the TLS handshake with the CDN itself (python ssl + MemoryBIO), sends the request with the
     swapped Referer, and reads just enough of the answer to see the HTTP status line + headers.
  2. It then works out the *server write key* of that connection (from the session keylog) and hands the key to
     the phone in a response header (X-Tls).  The key only protects this one connection and this one video part.
  3. From there on the relay only copies the raw encrypted TLS records from the CDN socket to the phone.
     The phone (sw.js + tlsdec.js, WebCrypto AES-GCM) decrypts them.

Anything that is not a plain 200/206 body (errors, redirects, playlists) or any problem (CDN has no TLS 1.2 /
no AES-GCM, no keylog) returns None, and the caller uses the normal path.

TLS_PASS=0 turns the whole thing off.
"""
import asyncio
import atexit
import hashlib
import hmac
import os
import ssl
import tempfile
import time

ENABLED = os.getenv("TLS_PASS", "1") != "0"
VERIFY_TLS = os.getenv("RAW_VERIFY_TLS", "1") != "0"
SESS_TTL = int(os.getenv("PASS_SESSION_TTL", "3600"))
STATS = {"ok": 0, "fail": 0, "resumed": 0}
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


def _master(cr):
    """master secret for this client_random from the keylog file (None if not there)"""
    want = b"CLIENT_RANDOM " + cr.hex().encode() + b" "
    try:
        with open(KEYLOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            data = f.read()
        for line in reversed(data.split(b"\n")):
            if line.startswith(want):
                return bytes.fromhex(line[len(want):].strip().decode())
    except Exception:
        pass
    return None


def _trim_keylog():
    try:
        if not _PENDING[0] and os.path.getsize(KEYLOG) > 262144:
            os.truncate(KEYLOG, 0)
    except Exception:
        pass


async def _handshake(host, port, cached):
    """-> (reader, writer, sslobj, client_random, server_random)"""
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port, limit=1 << 20), 10)
    try:
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = _ctx.wrap_bio(inc, out, server_hostname=host, session=cached[0] if cached else None)
        cr = sr = None
        got = bytearray()
        while True:
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            data = out.read()
            if data:
                if cr is None and len(data) >= 44 and data[0] == 22 and data[5] == 1:
                    cr = bytes(data[11:43])
                w.write(data)
                await w.drain()
            if done:
                break
            chunk = await asyncio.wait_for(r.read(65536), 10)
            if not chunk:
                raise ConnectionError("closed during handshake")
            if sr is None:
                got += chunk
                if len(got) >= 44 and got[0] == 22 and got[5] == 2:
                    sr = bytes(got[11:43])
            inc.write(chunk)
        if cr is None or sr is None:
            raise ValueError("no hello random")
        return r, w, obj, inc, out, cr, sr
    except BaseException:
        try:
            w.close()
        except Exception:
            pass
        raise


async def open_pass(host, port, path_q, headers_text, why=None):
    """Do the TLS handshake, send the request, read the answer head.
    headers_text: the request head WITHOUT the request line and without the final blank line (Host, Referer, Range ...)
    -> dict(reader, writer, raws, status, reason, hdr, k, s, q) or None (caller uses the normal path).
    On success the first `raws` (bytes already read from the socket, still locked) MUST be sent to the phone first."""
    if not ENABLED:
        return None
    if why is None:
        why = []
    _PENDING[0] += 1
    w = None
    try:
        cached = _SESS.get(host)
        if cached and time.time() - cached[2] > SESS_TTL:
            cached = None
        r, w, obj, inc, out, cr, sr = await _handshake(host, port, cached)
        cipher = obj.cipher()
        name = cipher[0]
        if cipher[1] != "TLSv1.2" or "GCM" not in name:
            why.append("cipher " + name)
            return None
        ms = _master(cr)
        if ms is None and obj.session_reused and cached:
            ms = cached[1]                                   # resumed: same master secret as the full handshake
        if ms is None:
            why.append("no keylog")
            return None
        klen = cipher[2] // 8
        h = hashlib.sha384 if name.endswith("SHA384") else hashlib.sha256
        kb = _prf(ms, b"key expansion", sr + cr, 2 * klen + 8, h)
        skey, siv = kb[klen:2 * klen], kb[2 * klen + 4:2 * klen + 8]
        if obj.session is not None:
            _SESS[host] = (obj.session, ms, time.time())
        if obj.session_reused:
            STATS["resumed"] += 1
        # --- request ---
        obj.write(("GET %s HTTP/1.1\r\n%s\r\n" % (path_q, headers_text)).encode("latin-1") + b"\r\n")
        w.write(out.read())
        await w.drain()
        # --- answer head (the locked bytes are kept so that the phone can decrypt them from the start) ---
        raws, plain = [], bytearray()
        while b"\r\n\r\n" not in plain:
            if len(plain) > 32768:
                why.append("head too big")
                return None
            chunk = await asyncio.wait_for(r.read(65536), 20)
            if not chunk:
                why.append("closed before head")
                return None
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
        head = bytes(plain).split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        st = head[0].split(" ", 2)
        status = int(st[1])
        hdr = []
        for ln in head[1:]:
            k, _, v = ln.partition(":")
            hdr.append((k.strip(), v.strip()))
        res = {"reader": r, "writer": w, "raws": raws, "status": status, "hdr": hdr,
               "k": skey.hex(), "s": siv.hex(), "q": 1, "name": name}
        w = None                                             # now owned by the caller
        STATS["ok"] += 1
        return res
    except Exception as ex:
        STATS["fail"] += 1
        why.append(repr(ex)[:100])
        return None
    finally:
        _PENDING[0] -= 1
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
        _trim_keylog()
