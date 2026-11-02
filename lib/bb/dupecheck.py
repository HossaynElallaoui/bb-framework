"""§3.3 pre-submission duplicate check.

Gate 4 (not_dup) only catches duplicates against *your own* registry. This
module widens the net before a report-writing cycle is sunk into something
already filed:

- known-issues: the program's own published known-issues list
  (programs/<slug>/known-issues.md), matched by token overlap with the
  finding summary — offline and deterministic.
- external: programs/<slug>/dupcheck.sh, an operator-provided hook that
  receives the finding summary as argv and prints `DUP: <reference>` lines
  for anything it recognizes (e.g. a HackerOne hacktivity search). Network
  access stays operator-controlled; a missing or failing hook is fail-open.

Both are advisory: they never flip gate 4 by themselves, they surface hits
so the operator decides before writing the report.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lib.bb import config

_STOP = {"the", "a", "an", "of", "in", "on", "for", "to", "and", "or", "is",
         "are", "with", "via", "that", "this", "it", "as", "at", "by", "be"}


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]{3,}", (text or "").lower())
            if t not in _STOP}


def load_known_issues(ws: Path) -> list[str]:
    p = Path(ws) / "known-issues.md"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip().lstrip("-* ").strip()
        if len(line) >= 8 and not line.startswith("#"):
            out.append(line)
    return out


def known_issues_hits(f: dict, ws: Path) -> list[dict]:
    """Match between the finding (summary + vuln_class) and each known-issue
    line. A line hits when it shares >= 40% of the finding's salient tokens,
    or shares >= 2 tokens including the vuln_class itself (long summaries
    dilute a plain ratio; the vuln class is the strongest duplicate signal)."""
    text = f"{f.get('summary', '')} {f.get('vuln_class', '')} " \
           f"{f.get('endpoint', '')}"
    ftoks = _tokens(text)
    cls = (f.get("vuln_class") or "").lower().strip()
    if not ftoks:
        return []
    hits = []
    for line in load_known_issues(ws):
        ltoks = _tokens(line)
        if not ltoks:
            continue
        overlap = ftoks & ltoks
        ratio = len(overlap) / max(len(ftoks), 1)
        anchored = bool(cls) and len(overlap) >= 2 and cls in overlap
        if ratio >= 0.4 or anchored:
            hits.append({"line": line[:200],
                         "matched": sorted(overlap)[:8]})
    return hits


def external_hits(f: dict, ws: Path, base: Path | None = None,
                  timeout: int = 60) -> list[str]:
    """Run the operator's dupcheck.sh hook if present. Prints `DUP: <ref>`
    lines for recognized prior reports; anything else is ignored."""
    base = base or config.root()
    hook = Path(ws) / "dupcheck.sh"
    if not hook.exists():
        return []
    try:
        r = subprocess.run([str(hook), f.get("summary", "")],
                           capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in (r.stdout or "").splitlines():
        m = re.match(r"\s*DUP\s*[:\-]\s*(.+)", line)
        if m:
            out.append(m.group(1).strip()[:200])
    return out


def check(f: dict, ws: Path | None, base: Path | None = None) -> dict:
    if ws is None:
        return {"known_issues": [], "external": [], "clean": True}
    ki = known_issues_hits(f, ws)
    ex = external_hits(f, ws, base)
    return {"known_issues": ki, "external": ex,
            "clean": not ki and not ex}
