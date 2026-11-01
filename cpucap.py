"""cpucap.py - HARD CPU LIMIT for the relay (Wispbyte kills a server that stays above ~15% CPU).

How: `python main.py` starts this governor first.  The governor starts the real relay as a child process and every
20 ms looks at how much CPU the child used (/proc/<pid>/stat).  The child may use CPU_LIMIT percent of one core on average;
if it uses more it is paused with SIGSTOP and continued with SIGCONT (like the 'cpulimit' tool).  While it is paused
no CPU is used at all, the sockets just fill up and TCP slows the video down by itself - nothing breaks, nothing is lost.
The governor itself only sleeps (about 0.2% CPU).

  CPU_LIMIT=11     percent of one core the relay may use (0 = governor off).  Default 11: measured peaks stay <= 13-14% in any 1 s window.
  CPU_BURST=0.01   cpu-seconds the relay may use in a quick burst (smaller = smoother, never a spike above the limit)
  CPU_CAP_LOG=1    print one line every 30 s: how much cpu was used and how long the relay was paused
"""
import os
import signal
import subprocess
import sys
import time

TICK = 0.02


def _cpu_seconds(pid, hz):
    """user+system cpu seconds of the whole process (all threads) - None if it cannot be read"""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read()
        rest = data[data.rindex(b")") + 2:].split()
        return (int(rest[11]) + int(rest[12])) / float(hz)      # utime + stime
    except Exception:
        return None


def _pdeathsig():
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)      # PR_SET_PDEATHSIG: child dies with the governor
    except Exception:
        pass


def govern(argv, env, limit, burst=0.01, log=False):
    """run argv as a child and keep its cpu at <= limit percent. returns the child's exit code"""
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    L = limit / 100.0
    child = subprocess.Popen(argv, env=env, preexec_fn=_pdeathsig)
    pid = child.pid
    stopped = [False]

    def forward(sig, _frame):
        try:
            if stopped[0]:
                os.kill(pid, signal.SIGCONT)
                stopped[0] = False
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, forward)

    print("[cap] CPU limit %.1f%% of one core (hard, SIGSTOP/SIGCONT governor), child pid %d" % (limit, pid), flush=True)
    last_cpu = _cpu_seconds(pid, hz) or 0.0
    last_t = time.monotonic()
    tokens = burst
    t_log, cpu_log, paused_log = last_t, last_cpu, 0.0
    while True:
        rc = child.poll()
        if rc is not None:
            return rc
        time.sleep(TICK)
        now = time.monotonic()
        cpu = _cpu_seconds(pid, hz)
        if cpu is None:
            continue
        tokens = min(burst, tokens + L * (now - last_t) - (cpu - last_cpu))
        last_t, last_cpu = now, cpu
        if tokens < 0:
            wait = min(-tokens / L, 1.0)
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped[0] = True
            except ProcessLookupError:
                continue
            t0 = time.monotonic()
            time.sleep(wait)
            if stopped[0]:
                try:
                    os.kill(pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                stopped[0] = False
            paused_log += time.monotonic() - t0
        if log and now - t_log >= 30:
            print("[cap] last %ds: cpu used %.1f%% | relay paused %.0f%% of the time" % (
                now - t_log, 100.0 * (cpu - cpu_log) / (now - t_log), 100.0 * paused_log / (now - t_log)), flush=True)
            t_log, cpu_log, paused_log = now, cpu, 0.0


def maybe_run(script):
    """call at the top of main.py (after .env is loaded). Runs the governor + child and exits, or returns to run normally."""
    if os.environ.get("CPU_CHILD") == "1":
        return
    try:
        limit = float(os.getenv("CPU_LIMIT", "11"))
    except ValueError:
        limit = 11.0
    if limit <= 0:
        return
    if _cpu_seconds(os.getpid(), 100) is None:
        print("[cap] /proc not readable - CPU limit is OFF", flush=True)
        return
    env = dict(os.environ, CPU_CHILD="1")
    rc = govern([sys.executable, "-u", script] + sys.argv[1:], env, limit,
                float(os.getenv("CPU_BURST", "0.01")), os.getenv("CPU_CAP_LOG", "0") == "1")
    sys.exit(rc)
