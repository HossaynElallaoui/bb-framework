"""Deterministic critic gate (`bb gate`).

The model-facing critic prompt still handles nuanced questions (evidence
sufficiency, refute plan, cheaper test), but the mechanizable checks are code:

  Q3  already-tried / is-known-failed
  Q7  scope
  Q8  skill-library checked
  +   state-changing method policy
  +   circuit breaker (stop hammering a failing host)

A specialist runs this immediately before acting. BLOCK means the action does
not happen. The gate is cheap and deterministic, so it can be called every turn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from lib.bb import config, policy, scope, statex
from lib.bb.scope_checker import extract_host_port
from lib.state import TargetState


@dataclass
class GateVerdict:
    allow: bool
    reasons: list[str] = field(default_factory=list)
    checks: dict = field(default_factory=dict)

    def render(self) -> str:
        lines = [f"VERDICT: {'ALLOW' if self.allow else 'BLOCK'}"]
        lines.append("REASON: " + ("; ".join(self.reasons) if self.reasons else "all checks passed"))
        for k, v in self.checks.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)


def evaluate(*, workspace: Path, target: str = "", cmd: str = "",
             method: str = "", mode: str = "bounty",
             skill_checked: bool = False, keywords: str = "",
             trivial: bool = False, force: bool = False,
             allow_unsafe: bool = False, base: Path | None = None) -> GateVerdict:
    base = base or config.root()
    reasons: list[str] = []
    checks: dict = {}

    # Q7 scope
    if target:
        ok, verdict = scope.check_target(target, workspace=workspace, mode=mode, base=base)
        checks["q7_scope"] = "PASS" if ok else f"DENY ({verdict.get('reason')})"
        if not ok:
            reasons.append(f"out of scope: {verdict.get('reason')}")
    else:
        checks["q7_scope"] = "not provided (skipped)"

    st = TargetState.load(workspace) if workspace else None

    # Q3 dedup / failed-path memory
    if cmd and st is not None:
        prior = st.already_tried(cmd)
        checks["q3_already_tried"] = "PASS" if not prior else f"BLOCK (recorded {prior.timestamp:.0f})"
        if prior and not force:
            reasons.append("command already recorded; explain what changed or pick a cheaper test")
        failed = st.is_known_failed(cmd)
        checks["q3_known_failed"] = "PASS" if not failed else "BLOCK"
        if failed:
            reasons.append("technique is a recorded dead end")
    else:
        checks["q3_already_tried"] = "not provided (skipped)"

    # method policy + circuit breaker. Infer the verb from the command when the
    # caller omitted --method, so `curl -X DELETE` cannot bypass the gate.
    inferred = False
    if not method and cmd:
        for pat in (r"(?:-X|--request)\s*([A-Za-z]+)", r"-X([A-Za-z]+)"):
            m = re.search(pat, cmd)
            if m:
                method, inferred = m.group(1).upper(), True
                break
        if not method and re.search(r"\bcurl\b|\bhttpie\b|\bhttp\s", cmd) and re.search(
                r"(?:-d|--data|--data-raw|--data-binary|--json|-F|--form)\b", cmd):
            method, inferred = "POST", True
    if method:
        if inferred:
            checks["method_source"] = "inferred from --cmd"
        ok, why = policy.SafeMethodPolicy.allow(method, mode, allow_unsafe=allow_unsafe)
        checks["method"] = "PASS" if ok else f"BLOCK ({why})"
        if not ok:
            reasons.append(why)
    if target:
        host = extract_host_port(target) or target
        breaker = policy.CircuitBreaker(workspace) if workspace else None
        if breaker:
            ok, why = breaker.allow(host)
            checks["circuit_breaker"] = "PASS" if ok else f"BLOCK ({why})"
            if not ok:
                reasons.append(why)

    # Q8 skill library
    if skill_checked:
        checks["q8_skill"] = "PASS (specialist confirmed)"
    elif trivial:
        checks["q8_skill"] = "PASS (trivial action)"
    else:
        matched = []
        if keywords:
            try:
                import sys
                real_scripts = Path(__file__).resolve().parents[2] / "scripts"
                for d in (base / "scripts", real_scripts):
                    if (d / "skills_lookup.py").exists() and str(d) not in sys.path:
                        sys.path.insert(0, str(d))
                import skills_lookup  # type: ignore
                matched = skills_lookup.search(keywords, limit=3)
            except Exception:
                matched = []
        if matched:
            checks["q8_skill"] = "PASS (matched " + ", ".join(m["path"] for m in matched[:2]) + ")"
        else:
            checks["q8_skill"] = "BLOCK (run `bb skills \"<keywords>\"` first, or pass --trivial)"
            reasons.append("skill library not checked for a non-trivial technique")

    return GateVerdict(allow=not reasons, reasons=reasons, checks=checks)
