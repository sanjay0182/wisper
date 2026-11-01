"""rtrace.py - one trace per request: every step the relay does, with its time and (where it can be measured) its real CPU.

Every request prints ONE block (all lines at once, so lines of two requests never mix):

  [req #12] pt GET -> 206  6.00MB  total 1853ms  host=cdn.example.com
  [req #12]   1. read request head from phone     wall    0.4ms  cpu    0.1ms | ...
  [req #12]   2. decode link + signature check    wall    0.2ms  cpu    0.2ms | ...
  ...
  [req #12] END total=1853ms | steps cpu=14.2ms (only the blocks that were measured) | whole-process cpu=210ms in this time | other requests running at the same time: up to 1

How to read the numbers
  wall  = real time the step took (includes waiting for the network).
  cpu   = real CPU time of the code of that step, measured only around code that runs WITHOUT waiting
          (one block of python / one openssl call / one syscall), so no other request is mixed in.
          '-' means: this step is mostly waiting, there is no separate CPU number.
  'whole-process cpu' = CPU of the whole python process between the start and the end of this request.
          If 'other requests running' is more than 0, that number also contains their work.

RELAY_LOG=0 switches all of this off (the 10 second [cpu] line stays).
"""
import itertools
import os
import time

ON = os.getenv("RELAY_LOG", "1") != "0"
_ids = itertools.count(1)
ACTIVE = [0]            # requests running right now


class _Blk:
    __slots__ = ("tr", "p")

    def __init__(self, tr):
        self.tr = tr

    def __enter__(self):
        self.p = time.process_time()

    def __exit__(self, *a):
        self.tr.cpu(time.process_time() - self.p)
        return False


class _NullBlk:
    def __enter__(self):
        return None

    def __exit__(self, *a):
        return False


class Null:
    """does nothing (RELAY_LOG=0, or no trace given): the code can call tr.lap(...) without checking"""
    kv = {}
    status = "-"
    bytes = 0
    id = 0

    def blk(self):
        return _NullBlk()

    def cpu(self, seconds):
        pass

    def lap(self, name, note=""):
        pass

    def note(self, text):
        pass

    def end(self, tail=""):
        pass


NULL = Null()


def new(kind="?", t0=None, p0=None):
    """a Trace, or NULL when RELAY_LOG=0"""
    return Trace(kind, t0, p0) if ON else NULL


class Trace:
    def __init__(self, kind="?", t0=None, p0=None):
        self.id = next(_ids)
        self.kind = kind
        self.kv = {}                    # extra facts for the first line (host, path, range ...)
        self.status = "-"
        self.bytes = 0
        self.t0 = self._m = t0 if t0 is not None else time.perf_counter()     # t0/p0: when the connection really started
        self.p0 = p0 if p0 is not None else time.process_time()
        self.rows = []                  # (name | None, wall ms, cpu ms | None, note)
        self._cpu = None                # cpu ms measured since the last lap
        self.cpu_sum = 0.0
        self.done = False
        ACTIVE[0] += 1
        self.max_others = ACTIVE[0] - 1

    def blk(self):
        """with tr.blk():  <code that does NOT wait>   -> its real cpu time is added to the next lap"""
        return _Blk(self)

    def cpu(self, seconds):
        """add CPU seconds that were measured around a block that does not wait (belongs to the next lap)"""
        ms = seconds * 1000.0
        self._cpu = ms if self._cpu is None else self._cpu + ms
        self.cpu_sum += ms

    def lap(self, name, note=""):
        """close a step: wall time since the previous lap, plus the cpu measured meanwhile"""
        now = time.perf_counter()
        self.rows.append((name, (now - self._m) * 1000.0, self._cpu, note))
        self._m = now
        self._cpu = None
        o = ACTIVE[0] - 1
        if o > self.max_others:
            self.max_others = o

    def note(self, text):
        """a line without time: a decision, a reason, an error"""
        self.rows.append((None, 0.0, None, text))

    def end(self, tail="end / close connection"):
        if self.done:
            return
        self.done = True
        now = time.perf_counter()
        if (now - self._m) * 1000.0 >= 0.05 or self._cpu is not None:
            self.lap(tail)
        ACTIVE[0] -= 1
        if not ON:
            return
        total = (now - self.t0) * 1000.0
        proc = (time.process_time() - self.p0) * 1000.0
        p = "[req #%d] " % self.id
        mb = self.bytes / 1048576.0
        head = "%s%s -> %s" % (p, self.kind, self.status)
        if self.bytes:
            head += "  %.2fMB" % mb
        head += "  total %.0fms" % total
        for k, v in self.kv.items():
            head += "  %s=%s" % (k, v)
        out = [head]
        n = 0
        for name, wall, cpu, note in self.rows:
            if name is None:
                out.append("%s      * %s" % (p, note))
                continue
            n += 1
            out.append("%s%3d. %-34s wall %8.1fms  cpu %s%s" % (
                p, n, name, wall, ("%7.2fms" % cpu) if cpu is not None else "      - ",
                (" | " + note) if note else ""))
        last = "%sEND total=%.0fms | steps cpu=%.1fms (only measured blocks) | whole-process cpu=%.0fms in this time | other requests at the same time: up to %d" % (
            p, total, self.cpu_sum, proc, self.max_others)
        if self.bytes and total > 0:
            last += " | %.2fMB at %.2fMB/s" % (mb, mb / (total / 1000.0))
        out.append(last)
        print("\n".join(out), flush=True)
