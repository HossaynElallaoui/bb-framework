"""Render a report from programs/_template/reports/finding-template.md.

The template is the structural source of truth (headings and order); this
module fills each section with finding data. Evidence is referenced by path
(never pasted), and obvious secrets are redacted even if an agent put them in
the finding JSON. The output is a draft for operator review; `bb` never
submits anything.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from lib.bb import config

SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s\"']+"), r"\1<redacted: see evidence>"),
    (re.compile(r"(?i)(\bcookie:\s*)[^\n\"']+"), r"\1<redacted: see evidence>"),
    (re.compile(r"(?i)(\bset-cookie:\s*)[^\n\"']+"), r"\1<redacted: see evidence>"),
    (re.compile(r"(?i)((?:password|passwd|secret|api[_-]?key|token)[\"'\s:=]+)[^\s\"',;}]+"),
     r"\1<redacted>"),
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b"), "<redacted-long-token>"),
]


def redact(text: str) -> tuple[str, bool]:
    changed = False
    out = text or ""
    for pat, repl in SECRET_PATTERNS:
        new = pat.sub(repl, out)
        if new != out:
            changed = True
            out = new
    return out, changed


def _evidence_rows(f: dict, base: Path, workspace: Path | None = None) -> list[tuple[str, str]]:
    rows = []
    notes = f.get("evidence_notes") or {}
    ev = f.get("evidence") or []
    if isinstance(ev, str):
        ev = [ev]
    for e in ev:
        e = str(e).strip()
        if not e:
            continue
        p = Path(e)
        if not p.is_absolute():
            cand = (Path(workspace) / e) if workspace else None
            p = cand if (cand is not None and cand.exists()) else (base / e)
        exists = p.exists()
        digest = ""
        if exists and p.is_file():
            try:
                digest = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
            except OSError:
                digest = ""
        proves = notes.get(e) if isinstance(notes, dict) else None
        proves = proves or ("captured output" + (f" (sha256:{digest})" if digest else ""))
        rows.append((e + ("" if exists else "  [MISSING]"), proves))
    if f.get("control_evidence"):
        rows.append((str(f["control_evidence"]), "control / negative baseline"))
    if f.get("curl_poc"):
        rows.append(("(inline curl PoC below)", "reproduction request"))
    return rows


def _bullets(items) -> str:
    if isinstance(items, str):
        items = [items]
    items = [str(i).strip() for i in (items or []) if str(i).strip()]
    return "\n".join(f"- {i}" for i in items) if items else "- (fill in)"


def _apply_template(tmpl: str, title: str, sections: dict[str, str]) -> str:
    """Replace the body under each `## Heading` in the template; append any
    section the template does not have. Non-section prose is preserved."""
    lines = tmpl.splitlines()
    if lines and lines[0].startswith("# "):
        lines = [f"# {title}"] + lines[1:]
    out: list[str] = []
    present: set[str] = set()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("## "):
            heading = line[3:].strip()
            present.add(heading)
            out.append(line)
            i += 1
            j = i
            while j < len(lines) and not lines[j].startswith("## "):
                j += 1
            # preserve a blank line, then the filled body (or the original when
            # the caller has no data for this section)
            out.append("")
            if heading in sections:
                out.append(sections[heading].strip())
                out.append("")
            else:
                out.extend(lines[i:j])
            i = j
        else:
            out.append(line)
            i += 1
    for heading, body in sections.items():
        if heading not in present:
            out += ["", f"## {heading}", "", body.strip(), ""]
    return "\n".join(out).rstrip() + "\n"


def render(finding: dict, base: Path | None = None,
           workspace: Path | None = None) -> tuple[str, bool]:
    base = base or config.root()
    cls = finding.get("vuln_class") or finding.get("vuln_type") or "Vulnerability"
    endpoint = finding.get("endpoint") or finding.get("url") or "(endpoint)"
    impact = finding.get("impact") or "(impact)"
    title = finding.get("title") or f"{cls} in {endpoint} allows {impact}"
    poc = finding.get("curl_poc") or finding.get("poc") or ""
    poc_red, poc_changed = redact(poc)

    ev_rows = _evidence_rows(finding, base, workspace)
    ev_table = "| Evidence path/reference | What it proves |\n|---|---|\n"
    ev_table += "\n".join(f"| `{p}` | {q} |" for p, q in ev_rows) if ev_rows else "| | |"

    sections = {
        "Summary": finding.get("summary") or "(fill in)",
        "Affected asset": _bullets([
            f"Host: {finding.get('host') or finding.get('target') or '(fill in)'}",
            f"Endpoint and HTTP method: {endpoint} {finding.get('method', '')}".strip(),
            f"Feature: {finding.get('feature', '(fill in)')}",
            f"Candidate classification/CWE: {finding.get('cwe') or cls}",
            f"Proposed severity and rationale: {finding.get('severity') or '(fill in)'}",
        ]),
        "Preconditions": _bullets([
            f"Account role and session state: {finding.get('preconditions_role', '(fill in)')}",
            f"Object ownership/tenant relationship: {finding.get('preconditions_ownership', '(fill in)')}",
            f"Required feature configuration: {finding.get('preconditions_config', '(fill in)')}",
        ]),
        "Reproduction": (
            (_bullets(finding.get("steps")) if finding.get("steps")
             else "(See the curl PoC and evidence paths below.)")
            + "\n\n```bash\n" + (poc_red or "# (fill in the exact curl command)") + "\n```\n\n"
            + "Baseline/control request and response: see the control evidence path below."
        ),
        "Expected behavior": finding.get("expected_behavior")
        or "(fill in the authorization/validation/state constraint that should be enforced)",
        "Observed behavior": finding.get("observed_behavior")
        or finding.get("impact") or "(fill in)",
        "Demonstrated impact": impact,
        "Controls and reproducibility": _bullets([
            f"Reproduction timestamp(s) in UTC: {finding.get('reproduced_at', '(fill in)')}",
            f"Repeated result: {finding.get('repeat_count', '(fill in)')}",
            f"Ownership and role controls: {finding.get('control_summary', '(see control evidence)')}",
            f"Session/cache/public-access controls: {finding.get('session_controls', '(fill in)')}",
        ]),
        "Evidence": ev_table + (
            "\n\n_Secret-looking values in the PoC were redacted; the raw request is in the evidence path._"
            if poc_changed else ""),
        "Suggested remediation": finding.get("remediation")
        or "(fill in the fix at the component that should enforce the failed constraint)",
        "Cleanup": finding.get("cleanup")
        or "Remove synthetic objects/accounts created for the proof.",
    }

    template_path = base / "programs" / "_template" / "reports" / "finding-template.md"
    if template_path.exists():
        body = _apply_template(template_path.read_text(), title, sections)
    else:
        parts = [f"# {title}", ""]
        for heading, content in sections.items():
            parts += [f"## {heading}", "", content, ""]
        body = "\n".join(parts).rstrip() + "\n"
    return body, poc_changed


def write_report(finding: dict, *, out: str | None = None,
                 workspace: Path | None = None, base: Path | None = None) -> tuple[Path, bool]:
    base = base or config.root()
    body, redacted = render(finding, base, workspace)
    if out:
        path = Path(out)
        if not path.is_absolute():
            path = base / path
    else:
        fid = re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding.get("id") or "finding")).strip(".-")
        fid = fid or "finding"
        if workspace:
            path = Path(workspace) / "findings" / f"{fid}-report.md"
        else:
            path = base / "findings" / f"{fid}-report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path, redacted
