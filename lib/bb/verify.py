"""§1.2 self-critique / second-opinion pass on hypothesis confirms.

A false-positive confirm is the most expensive mistake this framework can
make: in bounty mode it costs a full report-writing cycle, in HTB mode a
wasted branch. The specialist's own turn both proposes and commits the
confirm, so the framework adds a second, differently-prompted pass that runs
*after* a turn flips a hypothesis to `confirmed` and *before* anything
downstream consumes it.

Design constraints:
- Judgment call on existing evidence — the verifier gets the hypothesis, its
  stated test plan, the claimed result, and the recent action log. It runs
  no new actions (system prompt forbids tool use), so it adds no turn count
  to the hunt itself, only one cheap turn per confirm event.
- Deterministic effect: a KICKBACK reverts the hypothesis to `open` with the
  reason recorded and a mailbox message to the confirming specialist. An
  AGREE is recorded and the confirm stands.
- Fail-open: any server/model failure leaves the confirm standing (the run
  must not stall because the checker flaked).
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from lib.bb import statex

VERIFIER_SYSTEM = """You are the bb verifier — a skeptical, adversarial second
opinion on a hypothesis confirmation. Another agent just claimed a hypothesis
is CONFIRMED. Your only job is to find reasons that confirmation is NOT
justified. Do not run any commands or tools. Judge strictly from the material
provided below.

Attack the confirmation on these axes:
- Does the claimed result actually demonstrate the success criteria of the
  hypothesis's own test plan, or is it merely consistent with the hypothesis?
- Is a control / paired comparison present where the test plan implies one?
- Could the observed result have an innocent alternative explanation?
- Is referenced evidence actually shown, or only described?
- Is the confidence proportionate to what is shown?

Answer with EXACTLY ONE line and nothing else:
VERDICT: AGREE
or
VERDICT: KICKBACK — <one sentence naming the specific missing evidence or flaw>
"""

_KICKBACK_RE = re.compile(r"VERDICT\s*:\s*KICKBACK\b[—:-]?\s*(.*)", re.I)
_AGREE_RE = re.compile(r"VERDICT\s*:\s*AGREE\b", re.I)
_VERIFICATIONS_KEY = "bb_verifications"
_VERIFICATION_CAP = 50


def build_verify_prompt(hyp, actions: list[tuple[str, str]]) -> str:
    """All material comes from existing state — this is a judgment call, not
    a new action."""
    lines = [
        f"HYPOTHESIS {hyp.id}: {hyp.statement}",
        f"TEST PLAN: {hyp.test or '(none stated)'}",
        f"EVIDENCE ON RECORD: {hyp.evidence or '(none)'}",
        f"CLAIMED RESULT: {hyp.result or '(none)'}",
        f"CONFIDENCE CLAIMED: {hyp.confidence}",
    ]
    if actions:
        lines.append("RECENT ACTIONS (command -> observed result):")
        for cmd, summary in actions[-8:]:
            lines.append(f"  - {cmd} -> {summary}")
    else:
        lines.append("RECENT ACTIONS: (none recorded)")
    lines.append(
        "Examine whether CLAIMED RESULT proves the TEST PLAN's success "
        "criteria for HYPOTHESIS. Reply with exactly one VERDICT line.")
    return "\n".join(lines)


def parse_verdict(text: str) -> tuple[str, str]:
    """Returns (verdict, reason): verdict in {agree, kickback, unclear}."""
    text = text or ""
    m = _KICKBACK_RE.search(text)
    if m:
        reason = (m.group(1) or "").strip().splitlines()[0][:300]
        return "kickback", reason or "(no reason given)"
    if _AGREE_RE.search(text):
        return "agree", ""
    return "unclear", ""


def apply_kickback(workspace: Path, hyp_id: str, reason: str,
                   confirming_agent: str) -> bool:
    """Deterministically revert a confirm: status back to open, reason
    appended to the result, mailbox message to the confirming specialist."""
    changed = {"ok": False}

    def _f(s):
        h = s.hypotheses.get(hyp_id)
        if not h or h.status != "confirmed":
            return
        h.status = "open"
        stamp = time.strftime("%Y-%m-%d %H:%M")
        h.result = f"{(h.result or '').strip()} [kickback {stamp}: {reason}]".strip()
        h.updated_at = time.time()
        s.post_message(
            "verifier", confirming_agent,
            f"your confirm of {hyp_id} was kicked back by the second-opinion "
            f"pass: {reason} — gather the missing evidence (or a control "
            f"result) and re-confirm; do not treat it as confirmed", "request")
        s.post_message(
            "verifier", "critic-agent",
            f"kickback applied: {hyp_id} reverted to open — {reason}", "info")
        record = {"hyp_id": hyp_id, "verdict": "kickback", "reason": reason,
                  "agent": confirming_agent, "at": time.time()}
        log = s.extra.get(_VERIFICATIONS_KEY)
        if not isinstance(log, list):
            log = []
        log.append(record)
        s.extra[_VERIFICATIONS_KEY] = log[-_VERIFICATION_CAP:]
        changed["ok"] = True

    statex.locked_update(Path(workspace), _f)
    return changed["ok"]


def record_agree(workspace: Path, hyp_id: str, confirming_agent: str,
                 verdict: str = "agree") -> None:
    def _f(s):
        log = s.extra.get(_VERIFICATIONS_KEY)
        if not isinstance(log, list):
            log = []
        log.append({"hyp_id": hyp_id, "verdict": verdict, "reason": "",
                    "agent": confirming_agent, "at": time.time()})
        s.extra[_VERIFICATIONS_KEY] = log[-_VERIFICATION_CAP:]

    statex.locked_update(Path(workspace), _f)


def second_opinion(server, workspace: Path, hyp, confirming_agent: str,
                   model: str | None, actions: list[tuple[str, str]],
                   timeout: float = 240) -> dict:
    """One cheap verifier turn on a fresh session. Never raises: a failure
    returns verdict 'error' and the confirm stands (fail-open)."""
    out = {"hyp_id": hyp.id, "verdict": "error", "reason": "", "agent":
           confirming_agent}
    try:
        sid = server.create_session(workspace, title="bb verifier")
        res = server.prompt(sid, build_verify_prompt(hyp, actions),
                            directory=workspace, agent="build",
                            system=VERIFIER_SYSTEM, model=model,
                            timeout=timeout)
        out["tokens"] = res.tokens
        out["cost"] = res.cost
        verdict, reason = parse_verdict(res.text)
        out["verdict"], out["reason"] = verdict, reason
        if not res.ok and not res.text.strip():
            out["verdict"] = "error"
            out["reason"] = (res.error or "empty verifier turn")[:200]
    except Exception as exc:
        out["reason"] = f"verifier exception: {exc}"[:200]
    return out
