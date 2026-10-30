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

from worker import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SERVER_PORT") or os.getenv("PORT") or 8000)
    print("[relay] port=%s LINK_SECRET=%s check_ip=%s trust_proxy=%s" % (
        port, "set" if os.getenv("LINK_SECRET") else "MISSING", os.getenv("WORKER_CHECK_IP", "0"), os.getenv("WORKER_TRUST_PROXY", "0")), flush=True)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning", proxy_headers=False)
