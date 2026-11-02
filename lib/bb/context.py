"""Tiered state context for agent prompts.

The old prompt pasted every hypothesis, every failed path, and the entire
shared mailbox into every turn. Once sessions are reused, that is both
wasteful and redundant: the session already holds the role, mode, and prior
context. Continuation turns only need what changed.

HOT  : this agent's unread mail + the current hypothesis
WARM : new actions / hypothesis updates / milestones since its last turn
COLD : omitted; the prompt tells the agent the exact `bb state` command to
       fetch it on demand.

Injected state is capped (default 600 tokens, chars/4 estimate). Truncations
are logged to agent_logs/context.jsonl so the cap is observable rather than
silent.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

STATE_TOKEN_BUDGET = 600
_SKILL_MODULE = None
_SKILL_HINTS: dict[str, str] = {}
_TRUNCATIONS = 0


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _one_line(text: str, limit: int = 180) -> str:
    line = " ".join(str(text).split())
    return line if len(line) <= limit else line[:limit - 1] + "…"


def _load_skill_module(base: Path):
    global _SKILL_MODULE
    if _SKILL_MODULE is not None:
        return _SKILL_MODULE
    path = base / "scripts" / "skills_lookup.py"
    if not path.exists():
        return None
    try:
        spec = importlib.util.spec_from_file_location("bb_skills_lookup", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _SKILL_MODULE = mod
        return mod
    except Exception:
        return None


def skill_hint(base: Path, agent: str, target: str, machine: str,
               mode: str) -> str:
    """One cached best-match skill per agent per run."""
    key = f"{agent}|{target}|{machine}|{mode}"
    if key in _SKILL_HINTS:
        return _SKILL_HINTS[key]
    mod = _load_skill_module(base)
    hint = ""
    if mod is not None:
        query = f"{agent.replace('-agent', '')} {mode} {machine}"
        try:
            hits = mod.search(query, limit=1)
        except Exception:
            hits = []
        if hits:
            hit = hits[0]
            hint = f"{hit.get('path')} — {_one_line(hit.get('snippet', ''), 160)}"
    _SKILL_HINTS[key] = hint
    return hint


def _log_truncation(workspace: Path, payload: dict) -> None:
    global _TRUNCATIONS
    _TRUNCATIONS += 1
    try:
        path = Path(workspace) / "agent_logs" / "context.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps({"ts": time.time(), **payload}) + "\n")
    except OSError:
        pass


def _fit(sections: list[tuple[str, str]], budget_tokens: int,
         workspace: Path | None, agent: str) -> str:
    kept: list[str] = []
    spent = 0
    dropped: list[str] = []
    for title, body in sections:
        if not body.strip():
            continue
        block = f"{title}:\n{body.strip()}"
        cost = estimate_tokens(block)
        if spent + cost > budget_tokens and kept:
            dropped.append(title)
            continue
        if cost > budget_tokens:
            # A single oversized section: keep the head, drop the tail.
            chars = budget_tokens * 4
            block = block[:chars] + "\n… (truncated; query state for full text)"
            dropped.append(f"{title}:tail")
            cost = estimate_tokens(block)
        kept.append(block)
        spent += cost
    if dropped and workspace is not None:
        _log_truncation(workspace, {"agent": agent, "dropped": dropped,
                                    "kept": [s.split(":", 1)[0] for s in kept],
                                    "tokens": spent, "budget": budget_tokens})
    return "\n\n".join(kept)


def state_delta(state, agent: str, since: float = 0.0,
                budget_tokens: int = STATE_TOKEN_BUDGET,
                workspace: Path | None = None, hyp_offset: int = 0) -> str:
    """Build the HOT/WARM state block for one turn.

    hyp_offset > 0 (§1.3 speculative exploration): this specialist works the
    offset-th ranked open hypothesis instead of the top one, so parallel
    specialists explore competing hypotheses instead of colliding on the
    same pick. First-confirmed wins; the others get refuted/requeued by
    their own testing — same dedup/flock safety handles the race."""
    hot: list[str] = []
    if hyp_offset > 0:
        ranked = sorted((h for h in state.hypotheses.values() if h.status == "open"),
                        key=lambda h: h.score(), reverse=True)
        nxt = ranked[hyp_offset] if hyp_offset < len(ranked) else (
            ranked[0] if ranked else None)
        if nxt is not None and hyp_offset < len(ranked):
            hot.append(f"  assigned (speculative rank {hyp_offset + 1}): "
                       f"{nxt.id} — {_one_line(nxt.statement, 160)} "
                       f"[conf={nxt.confidence}, cost={nxt.cost}]")
        elif nxt is not None:
            hot.append(f"  assigned (speculative rank {hyp_offset + 1} unavailable — "
                       f"fewer open hypotheses): {nxt.id} — "
                       f"{_one_line(nxt.statement, 160)}")
        else:
            hot.append("  current: (no open hypothesis)")
    else:
        nxt = state.next_hypothesis()
        if nxt:
            hot.append(f"  current: {nxt.id} — {_one_line(nxt.statement, 160)} "
                       f"[conf={nxt.confidence}, cost={nxt.cost}]")
        else:
            hot.append("  current: (no open hypothesis)")

    unread = state.inbox(agent, unread_only=True)
    lines = []
    for m in unread[:3]:
        tag = m.msg_type + (f":{m.hyp_id}" if getattr(m, "hyp_id", "") else "")
        lines.append(f"  {m.id} from={m.from_agent} [{tag}] "
                     f"{_one_line(m.text, 160)}")
    if len(unread) > 3:
        lines.append(f"  … {len(unread) - 3} more unread; "
                     f"run `bb state $BB_WORKSPACE inbox --for {agent}`")
    hot_body = "\n".join(lines) if lines else "  (empty)"

    warm: list[str] = []
    fresh_actions = [a for a in state.actions.values() if a.timestamp >= since]
    fresh_actions.sort(key=lambda a: a.timestamp)
    for a in fresh_actions[-3:]:
        warm.append(f"  action: {_one_line(a.command, 100)} → "
                    f"{_one_line(a.result_summary, 90)}")
    changed = [h for h in state.hypotheses.values() if h.updated_at >= since]
    changed.sort(key=lambda h: h.updated_at)
    for h in changed[-3:]:
        warm.append(f"  hyp {h.id}: status={h.status} "
                    f"result={_one_line(h.result, 100)}")
    if state.milestones:
        warm.append("  milestones: " + ", ".join(
            f"{k}@{v:.0f}s" for k, v in state.milestones.items()))
    if state.failed_paths:
        warm.append(f"  known dead ends: {len(state.failed_paths)} "
                    f"(query `bb state $BB_WORKSPACE is-known-failed --desc ...`)")

    sections = [
        ("HOT — current hypothesis", "\n".join(hot)),
        ("HOT — your unread mail", hot_body),
        ("WARM — changes since your last turn", "\n".join(warm)),
    ]
    body = _fit(sections, budget_tokens, workspace, agent)
    # COLD is an instruction, not state: always emit it even when HOT/WARM
    # consume the whole state budget.
    cold = ("COLD — omitted: full history: `bb state $BB_WORKSPACE history "
            "--hyp <id>`; all mail: `bb state $BB_WORKSPACE inbox --for "
            f"{agent} --all`")
    return f"{body}\n\n{cold}" if body else cold


def full_state_summary(state, agent: str, budget_tokens: int = 900,
                       workspace: Path | None = None) -> str:
    """First-turn summary: current-board orientation without the full dump."""
    hyps = [h for h in state.hypotheses.values() if h.status == "open"]
    hyps.sort(key=lambda h: h.score(), reverse=True)
    hyp_lines = [f"  {h.id}: {_one_line(h.statement, 150)} "
                 f"[conf={h.confidence}, cost={h.cost}]" for h in hyps[:8]]
    if len(hyps) > 8:
        hyp_lines.append(f"  … {len(hyps) - 8} more open")
    actions = sorted(state.actions.values(), key=lambda a: a.timestamp,
                     reverse=True)[:6]
    act_lines = [f"  {_one_line(a.command, 110)} → "
                 f"{_one_line(a.result_summary, 110)}" for a in actions]
    mile = ", ".join(f"{k}@{v:.0f}s" for k, v in state.milestones.items())
    sections = [
        ("Open hypotheses (ranked)", "\n".join(hyp_lines) or "  (none)"),
        ("Recent actions", "\n".join(act_lines) or "  (none)"),
        ("Milestones", mile or "  (none)"),
        ("Dead ends", f"  {len(state.failed_paths)} recorded; "
                      "query `bb state $BB_WORKSPACE is-known-failed --desc ...`"),
    ]
    return _fit(sections, budget_tokens, workspace, agent)
