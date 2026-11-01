"""Wispbyte startup file (the panel runs:  python main.py).
Settings come from the file  .env  next to this file.  The port is the one the panel gives (SERVER_PORT)."""
import os


def _load_env(path):
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except FileNotFoundError:
        pass


_load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

import cpucap  # noqa: E402
cpucap.maybe_run(os.path.abspath(__file__))        # hard CPU limit: starts the real relay as a child and keeps it under CPU_LIMIT %

from worker import app  # noqa: E402

def _run_plain(port):
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning", access_log=False, proxy_headers=False,
                timeout_keep_alive=30, backlog=256)


async def _run_raw(port):
    """public port: raw pipe (video) ; 127.0.0.1:port+1: the normal app (everything else)"""
    import asyncio
    import uvicorn
    import rawpipe
    internal = int(os.getenv("INTERNAL_PORT") or (port + 1))
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=internal, log_level="warning", access_log=False,
                                        proxy_headers=False, timeout_keep_alive=5))
    task = asyncio.create_task(srv.serve())
    for _ in range(100):
        if srv.started or task.done():
            break
        await asyncio.sleep(0.1)
    try:
        _, w = await asyncio.open_connection("127.0.0.1", internal)
        w.close()
    except Exception:
        srv.should_exit = True
        raise RuntimeError("loopback port %s not usable" % internal)
    raw = await asyncio.start_server(lambda r, w: rawpipe.handle(r, w, internal), "0.0.0.0", port,
                                     limit=rawpipe.CHUNK * 2, backlog=256)
    import gc
    gc.collect(); gc.freeze(); gc.set_threshold(100000, 50, 50)     # almost no GC pauses/CPU
    print("[relay] raw pipe on :%s (app on 127.0.0.1:%s)" % (port, internal), flush=True)
    if os.getenv("RELAY_STATS", "0") == "1":
        asyncio.create_task(rawpipe.stats_loop())
    await asyncio.gather(task, raw.serve_forever())


if __name__ == "__main__":
    port = int(os.getenv("SERVER_PORT") or os.getenv("PORT") or 8000)
    print("[relay] port=%s LINK_SECRET=%s check_ip=%s trust_proxy=%s" % (
        port, "set" if os.getenv("LINK_SECRET") else "MISSING", os.getenv("WORKER_CHECK_IP", "0"), os.getenv("WORKER_TRUST_PROXY", "0")), flush=True)
    if os.getenv("RAW_PIPE", "1") != "0":
        try:
            import asyncio
            try:
                import uvloop
                uvloop.install()
            except Exception:
                pass
            asyncio.run(_run_raw(port))
        except RuntimeError as ex:
            print("[relay] raw pipe off (%s) - normal mode" % ex, flush=True)
            _run_plain(port)
    else:
        _run_plain(port)
