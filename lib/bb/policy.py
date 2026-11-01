"""Portable safety primitives: rate ceiling, circuit breaker, method policy,
and the AutopilotGuard stall detector.

These are deterministic infrastructure, not technique. They are wired into the
central capture-command runner and the run loop so "faster" can never mean
"over the agreed request ceiling".
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
UNSAFE_METHODS = {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}


@contextmanager
def _lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _read(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _write(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2))
    os.replace(tmp, path)


class RateLimiter:
    """Per-host minimum-interval limiter, persisted so separate agent
    subprocesses share one ceiling for the same workspace."""

    def __init__(self, workspace: Path, rate_per_min: float | None):
        self.workspace = Path(workspace)
        self.rate_per_min = rate_per_min
        self.path = self.workspace / ".ratelimit.json"
        self.lock = self.workspace / ".ratelimit.lock"

    def interval(self) -> float:
        if not self.rate_per_min or self.rate_per_min <= 0:
            return 0.0
        return 60.0 / float(self.rate_per_min)

    def wait_seconds(self, host: str, now: float | None = None) -> float:
        interval = self.interval()
        if interval <= 0:
            return 0.0
        now = now if now is not None else time.time()
        data = _read(self.path, {})
        last = float((data.get(host) or {}).get("last", 0))
        return max(0.0, interval - (now - last))

    def consume(self, host: str) -> float:
        """Record a request and return how long the caller should wait first."""
        interval = self.interval()
        if interval <= 0:
            return 0.0
        with _lock(self.lock):
            now = time.time()
            data = _read(self.path, {})
            last = float((data.get(host) or {}).get("last", 0))
            wait = max(0.0, interval - (now - last))
            data[host] = {"last": now + wait}
            _write(self.path, data)
        return wait

    def enforce(self, host: str, sleeper=time.sleep) -> float:
        wait = self.consume(host)
        if wait > 0:
            sleeper(wait)
        return wait


class CircuitBreaker:
    """Stop hammering a host after repeated failures."""

    def __init__(self, workspace: Path, threshold: int = 5, cooldown: float = 120.0):
        self.path = Path(workspace) / ".circuit.json"
        self.lock = Path(workspace) / ".circuit.lock"
        self.threshold = threshold
        self.cooldown = cooldown

    def allow(self, host: str, now: float | None = None) -> tuple[bool, str]:
        now = now if now is not None else time.time()
        rec = (_read(self.path, {}) or {}).get(host) or {}
        opened = float(rec.get("opened_at", 0) or 0)
        if opened and now - opened < self.cooldown:
            return False, f"circuit open for {host} ({int(self.cooldown - (now - opened))}s left)"
        return True, ""

    def record(self, host: str, success: bool) -> None:
        with _lock(self.lock):
            data = _read(self.path, {})
            rec = data.setdefault(host, {"failures": 0, "opened_at": 0})
            if success:
                rec["failures"] = 0
                rec["opened_at"] = 0
            else:
                rec["failures"] = int(rec.get("failures", 0)) + 1
                if rec["failures"] >= self.threshold:
                    rec["opened_at"] = time.time()
            _write(self.path, data)


class SafeMethodPolicy:
    """Conservative HTTP verb gate for bounty mode."""

    @staticmethod
    def allow(method: str, mode: str = "bounty", *, allow_unsafe: bool = False,
              allowlist: set[str] | None = None) -> tuple[bool, str]:
        m = (method or "GET").upper()
        if m in SAFE_METHODS:
            return True, ""
        if allow_unsafe or m in (allowlist or set()):
            return True, ""
        if m == "POST":
            return True, ""
        if mode == "htb":
            return True, ""
        return False, (f"{m} is a state-changing method and bounty mode default-denies it "
                       f"(pass --allow-unsafe or add it to the program's method allowlist)")


class AutopilotGuard:
    """Early-warning detector for the pathological-run failure mode.

    Calibrated from benchmark/runs: Connected solved in 23 actions / 1 dead end;
    Autopilot burned 196 actions / 26 dead ends / ~29.5h because nothing marked
    a stop milestone. We warn well before the latter profile, not after.
    """

    def __init__(self, actions_threshold: int = 60, dead_end_rate: float = 0.25,
                 min_actions: int = 20):
        self.actions_threshold = actions_threshold
        self.dead_end_rate = dead_end_rate
        self.min_actions = min_actions

    def evaluate(self, state) -> list[str]:
        warnings: list[str] = []
        actions = len(state.actions)
        dead = len(state.failed_paths)
        open_h = sum(1 for h in state.hypotheses.values() if h.status == "open")
        done = {"root", "flag", "validated-finding"} & set(state.milestones)
        if done:
            return warnings
        # "actions since the last milestone" is the signal that matters: a run
        # that marked `user` at action 30 and is now at 70 has 40 actions of
        # post-user work, not 70 actions of no progress.
        last_elapsed = max(state.milestones.values()) if state.milestones else 0.0
        since = sum(1 for a in state.actions.values()
                    if (a.timestamp - state.started_at) > last_elapsed)
        if since >= self.actions_threshold:
            warnings.append(
                f"{since} actions since the last milestone "
                f"(Connected benchmark solved in 23 total; threshold {self.actions_threshold})")
        if actions >= self.min_actions:
            rate = dead / max(actions, 1)
            if rate > self.dead_end_rate:
                warnings.append(
                    f"dead-end rate {rate:.0%} over {actions} actions "
                    f"(threshold {self.dead_end_rate:.0%}) — hypothesis quality is degrading")
        if open_h == 0 and actions > 0:
            warnings.append("no open hypotheses — agents are at risk of inventing busywork")
        return warnings
