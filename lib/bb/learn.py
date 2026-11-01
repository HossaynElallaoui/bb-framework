"""Post-run learning loop: turn a run's confirmed techniques (and its
negative results) into candidate skills, then commit only operator-approved
ones into skills/<category>/<name>.md.

Nothing is committed automatically. The dashboard Learn tab and
`bb learn --approve` are the review surface, which keeps run-specific noise
out of the skill library.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from lib.bb import config
from lib.state import TargetState

CATEGORY_RULES = [
    (r"kerberos|kerberoast|asrep|dcsync|bloodhound|adcs|ldap|ntlm|smb|acl|domain", "ad"),
    (r"sudo|suid|cap_setuid|capab|systemd|incron|cron|service|privesc|root", "privesc"),
    (r"aws|azure|gcp|s3|firebase|kubernetes|k8s|cloud|imds", "cloud"),
    (r"recon|subdomain|nmap|httpx|ffuf|gobuster|dns|scan", "recon"),
    (r"loot|credential|persist|pivot|lateral|relay|exfil", "postexploitation"),
    (r"graphql|api|rest|grpc|swagger", "api"),
    (r"xss|ssrf|sqli|idor|csrf|oauth|ssti|xxe|upload|deserial|smuggling|cors|lfi", "web"),
]


def candidates_path(workspace: Path) -> Path:
    return Path(workspace) / "learn-candidates.json"


def _classify(text: str) -> str:
    low = text.lower()
    for pat, cat in CATEGORY_RULES:
        if re.search(pat, low):
            return cat
    return "web"


def _cid(*parts: str) -> str:
    return "lc-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:10]


def _reusable_section(text: str) -> str:
    m = re.search(r"(?im)^#{1,6}\s*reusable technique\s*$", text)
    if not m:
        return ""
    start = m.end()
    nxt = re.search(r"(?m)^#{1,6}\s+\S", text[start:])
    return text[start:start + nxt.start()].strip() if nxt else text[start:].strip()


def generate(workspace: Path, base: Path | None = None) -> dict:
    base = base or config.root()
    workspace = Path(workspace)
    state = TargetState.load(workspace)
    out: list[dict] = []

    for h in sorted(state.hypotheses.values(), key=lambda x: x.updated_at):
        if h.status != "confirmed":
            continue
        text = f"{h.statement} {h.evidence} {h.result}"
        cat = _classify(text)
        name = config.slugify(h.statement, 70)
        body = f"""# {h.statement}

**Trigger:** {h.statement}
**Source:** `{config.rel(workspace, base)}` hypothesis `{h.id}`
**Evidence:** {h.evidence or '(see state.json)'}

## Procedure

1. Confirm the precondition: {h.evidence or '(record the observation that justified the hypothesis)'}
2. Run the smallest test: {h.test or '(see hypothesis test plan)'}
3. Observed result: {h.result or '(record the confirmed result)'}

## Pitfalls

- Re-check scope before reuse (this skill transfers technique, not authorization).
- Verify the same preconditions exist; do not assume the target is identical.
"""
        out.append({
            "id": _cid("hyp", h.id, h.statement), "kind": "confirmed-hypothesis",
            "name": name, "category": cat, "trigger": h.statement, "body": body,
            "source": f"hypothesis {h.id}", "approved": False, "committed": False,
        })

    for fid, entry in (state.extra.get("bb_findings") or {}).items():
        if not isinstance(entry, dict):
            continue
        cls = entry.get("vuln_class") or "vulnerability"
        endpoint = entry.get("endpoint") or entry.get("target") or ""
        impact = entry.get("impact") or ""
        text = f"{cls} {endpoint} {impact}"
        cat = _classify(text)
        name = config.slugify(f"{cls}-{endpoint or workspace.name}", 70)
        body = f"""# {cls} on {endpoint or workspace.name}

**Trigger:** when a similar {cls} surface appears on a comparable target
**Source:** validated finding `{fid}` in `{config.rel(workspace, base)}`
**Class:** {cls}
**Impact:** {impact or '(see finding report)'}

## Procedure

1. Reproduce the finding from its report draft (`findings/{fid}-report.md`).
2. Keep the control/negative baseline paired with the positive request.
3. Re-verify scope and preconditions before reuse.

## Pitfalls

- This skill transfers technique and evidence discipline, not authorization.
- Re-run the program's scope gate before touching a new host.
"""
        out.append({
            "id": _cid("finding", fid, cls, endpoint), "kind": "validated-finding",
            "name": name, "category": cat, "trigger": f"{cls} on {endpoint}",
            "body": body, "source": f"finding {fid}", "approved": False,
            "committed": False,
        })

    for name in ("writeup.md", "WRITEUP.md", "postmortem.md"):
        p = workspace / name
        if not p.exists():
            continue
        sec = _reusable_section(p.read_text(errors="ignore"))
        if len(sec) < 40:
            continue
        first = next((ln.strip("# ").strip() for ln in sec.splitlines() if ln.strip()), "reusable technique")
        cat = _classify(sec)
        slug = config.slugify(first, 70)
        body = f"""# {first}

**Trigger:** {first}
**Source:** `{config.rel(p, base)}` (REUSABLE TECHNIQUE section)

{sec}

## Pitfalls

- Re-check scope before reuse.
- Record which precondition was essential, not just the payload.
"""
        out.append({
            "id": _cid("writeup", str(p), sec[:200]), "kind": "writeup-technique",
            "name": slug, "category": cat, "trigger": first, "body": body,
            "source": name, "approved": False, "committed": False,
        })

    # Negative results are first-class: cluster dead ends into a guard skill.
    if len(state.failed_paths) >= 3:
        grouped: dict[str, list] = {}
        for fp in state.failed_paths:
            grouped.setdefault(_classify(fp.description), []).append(fp)
        for cat, items in grouped.items():
            if len(items) < 3:
                continue
            name = f"{cat}-dead-ends-{config.slugify(workspace.name, 24)}"
            lines = "\n".join(f"- **{fp.description}** — {fp.reason}" for fp in items)
            body = f"""# {cat} dead ends observed on {workspace.name}

**Trigger:** before retrying a {cat} path on a similar target
**Source:** `{config.rel(workspace, base)}` failed_paths ({len(items)} records)

## Known dead ends

{lines}

## Use

Check this list before proposing the same technique again. A dead end here is
conditional on the recorded reason — if the precondition changed (new creds,
new port, patched version), re-test deliberately and record why.
"""
            out.append({
                "id": _cid("neg", cat, workspace.name, str(len(items))),
                "kind": "negative-results", "name": name, "category": cat,
                "trigger": f"avoid known {cat} dead ends", "body": body,
                "source": "failed_paths", "approved": False, "committed": False,
            })

    payload = {"workspace": config.rel(workspace, base), "generated_at": config.iso(),
               "candidates": out}
    config.write_json(candidates_path(workspace), payload)
    return payload


def load(workspace: Path) -> dict:
    data = config.read_json(candidates_path(workspace), default=None)
    if not isinstance(data, dict):
        return {"workspace": config.rel(workspace), "generated_at": None, "candidates": []}
    data.setdefault("candidates", [])
    return data


def update_body(workspace: Path, candidate_id: str, body: str) -> dict | None:
    data = load(workspace)
    hit = None
    for c in data.get("candidates", []):
        if c.get("id") == candidate_id:
            c["body"] = body
            c["edited"] = True
            hit = c
    if hit:
        config.write_json(candidates_path(workspace), data)
    return hit


def approve(workspace: Path, candidate_id: str, value: bool = True) -> dict | None:
    data = load(workspace)
    hit = None
    for c in data.get("candidates", []):
        if c.get("id") == candidate_id:
            c["approved"] = bool(value)
            hit = c
    if hit:
        config.write_json(candidates_path(workspace), data)
    return hit


def commit(workspace: Path, base: Path | None = None) -> dict:
    base = base or config.root()
    data = load(workspace)
    written, skipped = [], []
    for c in data.get("candidates", []):
        if not c.get("approved") or c.get("committed"):
            continue
        cat = config.slugify(c.get("category") or "web", 24) or "web"
        slug = config.slugify(c.get("name") or c.get("trigger") or "technique", 80)
        dest = base / "skills" / cat / f"{slug}.md"
        if dest.exists():
            skipped.append(str(config.rel(dest, base)))
            c["committed"] = True
            c["commit_skipped"] = "exists"
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(c["body"])
        written.append(str(config.rel(dest, base)))
        c["committed"] = True
        c["committed_path"] = str(config.rel(dest, base))
    config.write_json(candidates_path(workspace), data)
    return {"written": written, "skipped": skipped}
