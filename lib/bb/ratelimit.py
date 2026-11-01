"""Shared adaptive concurrency + cooldown for `bb run`.

Free-tier providers do not fail uniformly: a 429 on one turn means every
other in-flight turn is probably about to hit the same wall. A fixed
ThreadPoolExecutor fan-out cannot react. This limiter gates each turn with:

  - AIMD: +1 concurrent turn after a short success streak, halve on rate
    limit; never below min_parallel.
  - Exponential cooldown persisted in .ratelimit.json so a restarted run (or
    a second bb process on the same workspace) honours the same backoff.
  - A simple start-time token bucket for an agreed per-minute ceiling.

No model calls, no probing: it only reacts to the provider's own errors.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path


RATE_LIMIT_MARKERS = (
    "rate limit", "ratelimited", "429", "too many requests", "quota",
    "overloaded", "capacity", "temporarily unavailable",
)


def is_rate_limit_error(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in RATE_LIMIT_MARKERS)


@contextmanager
def _file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class AdaptiveLimiter:
    def __init__(self, workspace: Path, max_parallel: int = 5,
                 min_parallel: int = 1, rate_per_min: float | None = None,
                 base_cooldown: float = 15.0, max_cooldown: float = 300.0,
                 success_streak: int = 3):
        self.workspace = Path(workspace)
        self.path = self.workspace / ".ratelimit.json"
        self.lock_path = self.workspace / ".ratelimit.lock"
        self.max_parallel = max(1, int(max_parallel))
        self.min_parallel = max(1, min(int(min_parallel), self.max_parallel))
        self.rate_per_min = float(rate_per_min or 0) or None
        self.base_cooldown = float(base_cooldown)
        self.max_cooldown = float(max_cooldown)
        self.success_streak = max(1, int(success_streak))

        self._cv = threading.Condition()
        self.active = 0
        self.current = self.max_parallel
        self.successes = 0
        self.consecutive_errors = 0
        self.cooldown_until = 0.0
        self.next_start = 0.0
        self.last_event = ""
        self._load()

    # ---- persistence ----

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict) -> None:
        try:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=2))
            os.replace(tmp, self.path)
        except OSError:
            pass

    def _load(self) -> None:
        with _file_lock(self.lock_path):
            rec = self._read().get("_adaptive") or {}
        try:
            self.current = max(self.min_parallel, min(
                self.max_parallel, int(rec.get("current", self.current))))
            self.cooldown_until = float(rec.get("cooldown_until", 0) or 0)
            self.next_start = float(rec.get("next_start", 0) or 0)
            self.consecutive_errors = int(rec.get("consecutive_errors", 0) or 0)
        except (TypeError, ValueError):
            pass

    def _persist(self) -> None:
        with _file_lock(self.lock_path):
            data = self._read()
            data["_adaptive"] = {
                "current": self.current,
                "cooldown_until": self.cooldown_until,
                "next_start": self.next_start,
                "consecutive_errors": self.consecutive_errors,
                "last_event": self.last_event,
                "updated": time.time(),
            }
            self._write(data)

    # ---- gating ----

    def _refresh_cooldown(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if getattr(self, "_cooldown_mtime", None) == mtime:
            return
        self._cooldown_mtime = mtime
        rec = self._read().get("_adaptive") or {}
        try:
            external = float(rec.get("cooldown_until", 0) or 0)
            self.cooldown_until = max(self.cooldown_until, external)
            self.next_start = max(self.next_start, float(rec.get("next_start", 0) or 0))
        except (TypeError, ValueError):
            pass

    def wait_slot(self, sleeper=time.sleep) -> float:
        """Block until a turn may start. Returns seconds spent waiting."""
        waited = 0.0
        while True:
            self._refresh_cooldown()
            now = time.time()
            if self.cooldown_until > now:
                delay = min(self.cooldown_until - now, 30.0)
                self.last_event = f"cooldown {self.cooldown_until - now:.0f}s"
                sleeper(delay)
                waited += delay
                continue
            with self._cv:
                if self.active < self.current:
                    if self.next_start > now:
                        delay = min(self.next_start - now, 5.0)
                    else:
                        self.active += 1
                        self.next_start = now + (
                            60.0 / self.rate_per_min if self.rate_per_min else 0.0)
                        self._persist()
                        return waited
                else:
                    delay = 0.25
            sleeper(delay)
            waited += delay

    def release(self, ok: bool = True, rate_limited: bool = False) -> None:
        with self._cv:
            self.active = max(0, self.active - 1)
            if rate_limited:
                self.consecutive_errors += 1
                self.current = max(self.min_parallel, self.current // 2)
                cooldown = min(self.max_cooldown,
                               self.base_cooldown * (2 ** (self.consecutive_errors - 1)))
                self.cooldown_until = max(self.cooldown_until, time.time() + cooldown)
                self.successes = 0
                self.last_event = (f"rate limited: parallel={self.current}, "
                                   f"cooldown={cooldown:.0f}s")
                self._persist()
            elif ok:
                # Deliberately conservative: step up only after a sustained
                # success streak, not after every single success, so we do not
                # walk straight back into the next 429.
                self.successes += 1
                self.consecutive_errors = 0
                if self.successes >= self.success_streak:
                    self.current = min(self.max_parallel, self.current + 1)
                    self.successes = 0
                    self.last_event = f"recovered: parallel={self.current}"
                    self._persist()
            self._cv.notify_all()

    def snapshot(self) -> dict:
        now = time.time()
        return {
            "parallel": self.current,
            "max_parallel": self.max_parallel,
            "active": self.active,
            "cooldown": max(0.0, self.cooldown_until - now),
            "rate_per_min": self.rate_per_min,
            "last_event": self.last_event,
        }
