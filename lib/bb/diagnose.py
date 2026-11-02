"""§2.4 stuck-turn auto-diagnosis.

When a specialist keeps failing/emptying turns, the old behavior was to
back off silently and move on — the operator only saw a stuck flag in the
dashboard after the fact. This adds a cheap deterministic diagnosis (no
model): is the agent blocked on inbox items, getting critic-gate BLOCKed,
starving on an empty hypothesis queue, or just rate-limited? The diagnosis
goes to the dashboard mailbox and, when the queue is empty, steers
recon-agent to generate hypotheses instead of the run silently timing out.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from lib.bb import statex


def _recent_blocks(workspace: Path, agent: str, window_s: float = 1800
                   ) -> list[dict]:
    path = Path(workspace) / "agent_logs" / "gates.jsonl"
    cutoff = time.time() - window_s
    out = []
    try:
        for line in path.read_text(errors="replace").splitlines()[-200:]:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if (d.get("agent") in (agent, "", None)
                    and d.get("verdict") == "BLOCK"
                    and float(d.get("ts") or 0) >= cutoff):
                out.append(d)
    except OSError:
        pass
    return out


def diagnose(workspace: Path, agent: str) -> dict:
    """Deterministic why-is-this-agent-stuck check. Returns {diagnosis,
    reasons, action} — action is 'steer-recon' when the queue is starving."""
    workspace = Path(workspace)
    reasons: list[str] = []
    try:
        from lib.state import TargetState
        st = TargetState.load(workspace)
    except Exception:
        return {"agent": agent, "diagnosis": "state unreadable", "reasons": [],
                "action": "none"}
    unread = st.inbox(agent, unread_only=True)
    if unread:
        reasons.append(f"{len(unread)} unread inbox item(s) — dependency on "
                       f"another agent's result")
    blocks = _recent_blocks(workspace, agent)
    if len(blocks) >= 2:
        last = (blocks[-1].get("reason") or "")[:120]
        reasons.append(f"critic gate BLOCKed {len(blocks)}x recently "
                       f"(last: {last})")
    open_hyps = [h for h in st.hypotheses.values() if h.status == "open"]
    if not open_hyps:
        reasons.append("hypothesis queue is empty — nothing cheap to work")
    lim = statex.get_extra(workspace, "ratelimit", None)
    if isinstance(lim, dict) and lim.get("parallel") == 1:
        reasons.append("limiter at 1 slot — rate ceiling, not agent stuck")
    if not reasons:
        return {"agent": agent, "diagnosis": "no deterministic blocker found "
                "(likely provider flakiness)", "reasons": [], "action": "none"}
    action = "steer-recon" if not open_hyps and not unread else "none"
    return {"agent": agent, "diagnosis": "; ".join(reasons),
            "reasons": reasons, "action": action}


def handle_stuck(workspace: Path, agent: str, failures: int) -> dict:
    """Called by the runner when an agent accumulates consecutive failures.
    Posts the diagnosis to the dashboard; steers recon when starving."""
    if failures < 2:
        return {}
    d = diagnose(workspace, agent)
    if d.get("diagnosis") in (None, ""):
        return {}
    try:
        def _post(s):
            s.post_message("bb", "dashboard",
                           f"stuck-diagnosis {agent} ({failures} failed turns): "
                           f"{d['diagnosis']}", "status")
        statex.locked_update(Path(workspace), _post)
    except Exception:
        pass
    if d.get("action") == "steer-recon":
        try:
            def _m(s):
                s.post_message("bb", "recon-agent",
                               "hypothesis queue is empty while specialists "
                               "stall — generate cheap open hypotheses from "
                               "your latest recon output now", "request")
            statex.locked_update(Path(workspace), _m)
        except Exception:
            pass
    return d
