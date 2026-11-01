"""Workspace-scoped extensions on top of lib/state.py.

state.py intentionally owns a small schema and preserves unknown top-level
keys verbatim. We use that escape hatch for run-driver metadata (sessions,
heartbeat, pause sentinel, crash log) instead of growing the core schema.
Every mutation here takes the same `.state.lock` flock the state.py CLI uses.
"""

from __future__ import annotations

import fcntl
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from lib.state import TargetState
from lib.bb import config

SESSION_KEY = "bb_sessions"
HEARTBEAT_KEY = "bb_heartbeat"
PAUSE_KEY = "pause_after_turn"
FAILURES_KEY = "bb_failures"
WARNINGS_KEY = "bb_warnings"
RESUME_KEY = "bb_resume"
TOKENS_KEY = "bb_tokens"


@contextmanager
def _lock(workspace: Path):
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    lock_path = workspace / ".state.lock"
    with open(lock_path, "a") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def locked_update(workspace: Path, mutate: Callable[[TargetState], None]) -> TargetState:
    """Load -> mutate -> save under the shared state lock."""
    workspace = Path(workspace)
    with _lock(workspace):
        state = TargetState.load(workspace)
        mutate(state)
        state.save()
    return state


def get_extra(workspace: Path, key: str, default=None):
    state = TargetState.load(workspace)
    return state.extra.get(key, default)


def set_extra(workspace: Path, key: str, value) -> None:
    def _m(s: TargetState):
        s.extra[key] = value
    locked_update(workspace, _m)


def set_many(workspace: Path, values: dict) -> None:
    def _m(s: TargetState):
        for k, v in values.items():
            s.extra[k] = v
    locked_update(workspace, _m)


# ---- session continuity -------------------------------------------------

def get_sessions(workspace: Path) -> dict[str, str]:
    sessions = get_extra(workspace, SESSION_KEY, {}) or {}
    return {k: v for k, v in sessions.items() if isinstance(v, str) and v.startswith("ses_")}


def set_session(workspace: Path, agent: str, session_id: str) -> None:
    def _m(s: TargetState):
        sessions = dict(s.extra.get(SESSION_KEY, {}) or {})
        sessions[agent] = session_id
        s.extra[SESSION_KEY] = sessions
    locked_update(workspace, _m)


def clear_sessions(workspace: Path) -> None:
    def _m(s: TargetState):
        s.extra[SESSION_KEY] = {}
    locked_update(workspace, _m)


# ---- heartbeat / resumability ------------------------------------------

def heartbeat(workspace: Path, **fields) -> None:
    payload = {"epoch": time.time(), "at": config.iso(), **fields}
    def _m(s: TargetState):
        prev = s.extra.get(HEARTBEAT_KEY, {}) or {}
        merged = {**prev, **payload}
        merged["rounds_completed"] = max(
            int(prev.get("rounds_completed", 0)),
            int(payload.get("rounds_completed", prev.get("rounds_completed", 0)) or 0),
        )
        s.extra[HEARTBEAT_KEY] = merged
        # Explicit top-level resumability key (also readable by external tools).
        s.extra["last_active_epoch"] = payload["epoch"]
    locked_update(workspace, _m)


def last_active(workspace: Path) -> dict:
    return get_extra(workspace, HEARTBEAT_KEY, {}) or {}


def is_interrupted(workspace: Path) -> tuple[bool, str]:
    hb = last_active(workspace)
    if not hb:
        return False, "no heartbeat recorded"
    state = TargetState.load(workspace)
    done = {"root", "flag", "validated-finding"} & set(state.milestones)
    if done:
        return False, f"completed ({', '.join(sorted(done))})"
    age = time.time() - float(hb.get("epoch", 0))
    if age > 900 and hb.get("phase") in ("running", "turn"):
        return True, (f"interrupted mid-round {hb.get('round', '?')} "
                      f"({int(age // 60)}m since last heartbeat)")
    return False, f"last heartbeat {int(age)}s ago (round {hb.get('round', '?')})"


# ---- operator pause sentinel -------------------------------------------

def request_pause(workspace: Path, value: bool = True) -> None:
    set_extra(workspace, PAUSE_KEY, bool(value))


def pause_requested(workspace: Path) -> bool:
    return bool(get_extra(workspace, PAUSE_KEY, False))


def clear_pause(workspace: Path) -> None:
    request_pause(workspace, False)


# ---- critic-gate trace (dashboard status) ------------------------------

def record_gate(workspace: Path, allow: bool, command: str = "",
                agent: str = "", reason: str = "") -> None:
    """Append a gate verdict so the dashboard can show why an agent is idle.

    Agent attribution is best-effort: callers may pass --agent, otherwise we
    use the heartbeat's current agent (parallel turns can make that ambiguous).
    """
    workspace = Path(workspace)
    if not agent:
        agent = (last_active(workspace) or {}).get("agent") or ""
    rec = {"ts": time.time(), "agent": agent,
           "verdict": "ALLOW" if allow else "BLOCK",
           "command": (command or "")[:300], "reason": (reason or "")[:300]}
    try:
        path = workspace / "agent_logs" / "gates.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


# ---- crash / API-error memory -----------------------------------------

def record_failure(workspace: Path, agent: str, reason: str) -> None:
    def _m(s: TargetState):
        log = list(s.extra.get(FAILURES_KEY, []) or [])
        log.append({"epoch": time.time(), "agent": agent, "reason": reason[:500]})
        s.extra[FAILURES_KEY] = log[-100:]
    locked_update(workspace, _m)


def failures(workspace: Path) -> list[dict]:
    return get_extra(workspace, FAILURES_KEY, []) or []


def set_warnings(workspace: Path, warnings: list[str]) -> None:
    def _m(s: TargetState):
        s.extra[WARNINGS_KEY] = warnings[-20:]
    locked_update(workspace, _m)


def warnings(workspace: Path) -> list[str]:
    return get_extra(workspace, WARNINGS_KEY, []) or []


# ---- token / rate accounting ------------------------------------------

def _blank_tokens() -> dict:
    return {"total": 0, "input": 0, "output": 0, "reasoning": 0,
            "cache": {"read": 0, "write": 0}}


def merge_tokens(dst: dict, src: dict) -> None:
    for key in ("total", "input", "output", "reasoning"):
        dst[key] = int(dst.get(key, 0)) + int((src or {}).get(key) or 0)
    cache = dst.setdefault("cache", {"read": 0, "write": 0})
    for key in ("read", "write"):
        cache[key] = int(cache.get(key, 0)) + int(((src or {}).get("cache") or {}).get(key) or 0)


def record_tokens(workspace: Path, agent: str, tokens: dict, cost: float = 0.0,
                  duration: float = 0.0) -> dict:
    def _m(s: TargetState):
        agg = s.extra.get(TOKENS_KEY)
        if not isinstance(agg, dict):
            agg = {"total": _blank_tokens(), "agents": {}, "turns": 0}
        agg["turns"] = int(agg.get("turns", 0)) + 1
        agg["total"] = agg.get("total") or _blank_tokens()
        merge_tokens(agg["total"], tokens)
        agg["cost"] = float(agg.get("cost", 0.0)) + float(cost or 0.0)
        agents = agg.setdefault("agents", {})
        a = agents.get(agent) or {"tokens": _blank_tokens(), "turns": 0,
                                  "cost": 0.0, "duration": 0.0}
        a["tokens"] = a.get("tokens") or _blank_tokens()
        merge_tokens(a["tokens"], tokens)
        a["turns"] = int(a.get("turns", 0)) + 1
        a["cost"] = float(a.get("cost", 0.0)) + float(cost or 0.0)
        a["duration"] = float(a.get("duration", 0.0)) + float(duration or 0.0)
        agents[agent] = a
        agg["updated"] = time.time()
        s.extra[TOKENS_KEY] = agg
    locked_update(workspace, _m)
    return get_extra(workspace, TOKENS_KEY, {}) or {}


def token_summary(workspace: Path) -> dict:
    return get_extra(workspace, TOKENS_KEY, {}) or {}


# ---- resume snapshot ---------------------------------------------------

def resume_snapshot(workspace: Path) -> dict:
    state = TargetState.load(workspace)
    unread = {
        agent: len(state.inbox(agent, unread_only=True))
        for agent in config.ROLE_SPECIALISTS
    }
    hb = last_active(workspace)
    interrupted, why = is_interrupted(workspace)
    nxt = state.next_hypothesis()
    return {
        "workspace": config.rel(workspace),
        "target": state.target,
        "mode": state.mode,
        "milestones": sorted(state.milestones),
        "open_hypotheses": sum(1 for h in state.hypotheses.values() if h.status == "open"),
        "next_hypothesis": nxt.id if nxt else None,
        "sessions": get_sessions(workspace),
        "unread": unread,
        "paused": pause_requested(workspace),
        "heartbeat": hb,
        "interrupted": interrupted,
        "interrupted_reason": why,
        "failures": len(failures(workspace)),
    }
