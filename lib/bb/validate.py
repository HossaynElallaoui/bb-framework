"""Deterministic finding validator: 4 gates + the 7-question critic gate.

This is the callable twin of the upstream interactive `validate.py`, scoped to
`bb`'s workspace model. No prompts, no model calls. Q7 (scope) and Q8 (skill
library) are answered by code; the other five questions are answered from
finding fields (or `--answers` JSON), exactly as the operator/specialist
recorded them. A finding only becomes `validated_finding` when every gate and
every question passes.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from lib.bb import config, scope, statex
from lib.bb.scope_checker import _normalize_and_parse  # canonical URL parser

AUTH_CLASSES = {"idor", "bola", "auth-bypass", "ato", "bac", "access-control",
                "privilege", "privilege-escalation", "broken-access-control"}
CHAIN_REQUIRED = {
    "open-redirect": "OAuth redirect_uri -> auth-code/token theft (ATO)",
    "cors": "credentialed request that exfiltrates user PII",
    "csrf": "sensitive action (funds transfer, email/password change, delete)",
    "host-header": "password-reset email that uses the injected host",
    "self-xss": "CSRF that triggers it on a victim",
    "subdomain-takeover": "OAuth redirect_uri or cookie scope on the taken-over host",
    "graphql-introspection": "auth-bypass mutation or IDOR reachable via the schema",
}

PLACEHOLDERS = {"", "todo", "tbd", "n/a", "na", "none", "-", "[fill in]"}


def _clean(v) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _canon_class(v: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (v or "").lower()).strip("-")
    alias = {"broken-access-control": "bac", "access-control": "bac",
             "privilege-escalation": "privilege"}
    return alias.get(s, s)


def _norm_target(target: str) -> str:
    t = _clean(target)
    if not t:
        return ""
    if "://" not in t:
        t = "https://" + t
    parsed = _normalize_and_parse(t)
    if parsed is None:
        return t
    _kind, host, port, path, scheme = parsed
    host_s = str(host)
    if port is not None:
        host_s += f":{port}"
    return f"{scheme}://{host_s}{path}"


def dup_key(finding: dict) -> str:
    cls = _canon_class(finding.get("vuln_class") or finding.get("vuln_type"))
    host_path = _norm_target(finding.get("target") or finding.get("url") or "")
    try:
        u = urlparse(host_path)
        host_path = (u.hostname or "") + (u.path or "")
    except ValueError:
        pass
    fingerprint = _clean(finding.get("fingerprint"))
    blob = fingerprint or f"{cls}|{host_path.lower()}"
    return hashlib.sha256(blob.encode()).hexdigest()[:24]


# ---- finding storage ----------------------------------------------------

def find_finding(finding_id: str, workspace: Path | None = None,
                 base: Path | None = None) -> Path | None:
    base = base or config.root()
    if not finding_id:
        return None
    p = Path(finding_id)
    if p.is_file() and p.suffix == ".json":
        return p.resolve()
    # IDs are names, not paths: refuse traversal before joining a root.
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}", finding_id)
            or finding_id.startswith(".") or ".." in finding_id):
        return None
    roots = [base / "findings"]
    if workspace:
        roots.insert(0, Path(workspace) / "findings")
    roots += sorted((base / "programs").glob("*/findings"))
    for r in roots:
        cand = r / f"{finding_id}.json"
        if cand.is_file():
            return cand
        for hit in sorted(r.glob(f"{finding_id}*.json")):
            return hit
    return None


def load_finding(path: Path) -> dict:
    data = config.read_json(path, default=None)
    if not isinstance(data, dict):
        raise ValueError(f"finding is not a JSON object: {path}")
    data.setdefault("id", Path(path).stem)
    return data


def save_finding(path: Path, finding: dict) -> None:
    config.write_json(path, finding)


def registry_path(base: Path | None = None) -> Path:
    return (base or config.root()) / "findings" / "_registry.jsonl"


def load_registry(base: Path | None = None) -> list[dict]:
    p = registry_path(base)
    out = []
    if not p.exists():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if isinstance(d, dict):
                out.append(d)
        except ValueError:
            continue
    return out


def append_registry(entry: dict, base: Path | None = None) -> None:
    p = registry_path(base)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


# ---- deterministic gates ------------------------------------------------

def gate1_is_real(f: dict) -> tuple[bool, dict]:
    cls = _canon_class(f.get("vuln_class") or f.get("vuln_type"))
    evidence = f.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    has_control = bool(f.get("control_pair") or f.get("control_evidence")
                       or any("control" in str(e).lower() for e in evidence))
    notes = {
        "reproduced": bool(f.get("reproduced")),
        "deterministic": bool(f.get("deterministic")),
        "not_documented": bool(f.get("not_documented")),
        "control_pair": has_control,
    }
    if cls in AUTH_CLASSES:
        notes["identity_proven"] = bool(f.get("identity_proven"))
    ok = all(notes.values())
    if not ok:
        notes["reason"] = "not_reproducible_or_no_control" if not (
            notes["reproduced"] and notes["deterministic"]) else "identity_or_control_not_proven"
    return ok, notes


def gate2_in_scope(f: dict, workspace: Path | None, base: Path | None) -> tuple[bool, dict]:
    target = _clean(f.get("target") or f.get("url"))
    if not target:
        return False, {"reason": "no target", "in_scope": False}
    mode = _clean(f.get("mode"))
    if not mode:
        ws_parts = set(Path(workspace).parts) if workspace else set()
        mode = "htb" if (f.get("htb") or "labs" in ws_parts or "HTB" in ws_parts) else "bounty"
    program = _clean(f.get("program")) or None
    ok, verdict = scope.check_target(target, program=program, workspace=workspace,
                                     mode=mode, base=base)
    return ok, {**verdict, "reason": verdict.get("reason", "")}


def gate3_exploitable(f: dict, base: Path | None, workspace: Path | None = None) -> tuple[bool, dict]:
    impact = _clean(f.get("impact"))
    poc = _clean(f.get("curl_poc") or f.get("poc"))
    evidence = f.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    evidence = [_clean(e) for e in evidence if _clean(e)]
    missing = []
    for e in evidence:
        p = Path(e)
        if not p.is_absolute():
            # evidence paths in a finding are normally workspace-relative
            cand = (Path(workspace) / e) if workspace else None
            if cand is not None and cand.exists():
                p = cand
            else:
                p = (base or config.root()) / e
        if not p.exists():
            missing.append(e)
    poc_ok = bool(poc) and poc.lower() not in {"skip", "none", "n/a"} and not poc.startswith("TODO")
    impact_ok = impact.lower() not in PLACEHOLDERS and len(impact) >= 10
    ok = (poc_ok and impact_ok and not bool(f.get("unrealistic_preconditions"))
          and not missing)
    notes = {
        "impact": impact_ok, "curl_poc": poc_ok,
        "no_unrealistic_preconditions": not bool(f.get("unrealistic_preconditions")),
        "evidence_paths_exist": not missing,
        "missing_evidence": missing,
    }
    if not ok:
        notes["reason"] = ("missing_evidence" if missing else
                           "no_reproducible_impact" if not poc_ok else
                           "weak_impact" if not impact_ok else "unrealistic_privileges")
    return ok, notes


def gate4_not_dup(f: dict, base: Path | None) -> tuple[bool, dict]:
    key = dup_key(f)
    fid = _clean(f.get("id"))
    dupes = [e for e in load_registry(base)
             if e.get("dup_key") == key and e.get("finding_id") != fid
             and e.get("status") == "validated_finding"]
    if _clean(f.get("duplicate_of")):
        return False, {"reason": f"marked duplicate_of={f['duplicate_of']}",
                       "dup_key": key, "duplicates": [f["duplicate_of"]]}
    ok = not dupes
    return ok, {"dup_key": key, "duplicates": [d.get("finding_id") for d in dupes],
                "reason": "" if ok else "duplicate_or_already_disclosed"}


def _skill_library_checked(f: dict, base: Path | None) -> tuple[bool, list[str]]:
    used = f.get("skills_used") or []
    if isinstance(used, str):
        used = [used]
    paths = []
    for s in used:
        p = Path(s)
        if not p.is_absolute():
            p = (base or config.root()) / s
        if p.exists():
            paths.append(str(p))
    if f.get("skill_checked") and not paths:
        return True, paths
    if paths:
        return True, paths
    # cheap deterministic fallback: does any learned/packaged skill slug match
    # the vuln class? This is the same evidence Q8 asks the specialist for.
    cls = _canon_class(f.get("vuln_class") or f.get("vuln_type"))
    if not cls:
        return False, []
    tokens = [t for t in re.split(r"[-_]", cls) if len(t) >= 3]
    roots = config.load_skill_roots(base)
    for rname in roots["flat_roots"] + roots["packaged_roots"]:
        r = (base or config.root()) / rname
        if not r.exists():
            continue
        for md in r.rglob("*.md"):
            name = md.stem.lower()
            if all(t in name for t in tokens):
                return True, [config.rel(md, base)]
    return False, []


def questions(f: dict, g2: dict, base: Path | None) -> list[dict]:
    def q(n, text, ok, detail=""):
        return {"n": n, "question": text, "pass": bool(ok), "detail": detail}

    summary = _clean(f.get("summary") or f.get("statement"))
    evidence = f.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    q1 = len(summary) >= 15 and any(w in summary.lower() for w in (
        "allow", "expose", "read", "access", "execute", "bypass", "leak", "delete", "modify"))
    skill_ok, skill_paths = _skill_library_checked(f, base)
    return [
        q(1, "Falsifiable purpose (what are we proving?)", q1, summary[:120]),
        q(2, "Evidence supports it", bool(evidence) or bool(_clean(f.get("curl_poc"))),
          f"{len(evidence)} evidence path(s)"),
        q(3, "Not already tested", not bool(f.get("already_tried")),
          "already_tried=true" if f.get("already_tried") else ""),
        q(4, "No cheaper open test", not bool(f.get("cheaper_test")),
          _clean(f.get("cheaper_test")) if f.get("cheaper_test") else ""),
        q(5, "Clear confirm/refute signal", bool(_clean(f.get("confirm_refute"))),
          _clean(f.get("confirm_refute"))[:120]),
        q(6, "Plan for the refute case", bool(_clean(f.get("refute_plan"))),
          _clean(f.get("refute_plan"))[:120]),
        q(7, "Inside documented scope (deterministic)", bool(g2.get("in_scope")),
          g2.get("reason", "")),
        q(8, "Skill library checked (deterministic)", skill_ok,
          ", ".join(skill_paths[:3])),
    ]


def _kill_signals(f: dict) -> list[str]:
    cls = _canon_class(f.get("vuln_class") or f.get("vuln_type"))
    out = []
    if cls == "cors" and f.get("acao") in ("*", None) and not f.get("acac"):
        out.append("CORS without Access-Control-Allow-Credentials:true — no credentialed exfil")
    if str(f.get("nuclei_severity") or "").lower() == "info":
        out.append("nuclei info-severity match — version detection, not exploitation")
    if cls == "ssrf" and str(f.get("oob_protocol") or "").lower() == "dns" and not f.get("internal_data"):
        out.append("SSRF DNS callback only — no internal service data returned")
    if cls in CHAIN_REQUIRED and not f.get("chain_proven"):
        out.append(f"chain required but not proven: {CHAIN_REQUIRED[cls]}")
    if cls in AUTH_CLASSES and not f.get("identity_proven"):
        out.append("auth-class finding needs cross-identity proof (Q8 identity check)")
    return out


def validate(f: dict, *, workspace: Path | None = None,
             base: Path | None = None, write: bool = True) -> dict:
    base = base or config.root()
    cls = _canon_class(f.get("vuln_class") or f.get("vuln_type"))
    kills = _kill_signals(f)
    g1, n1 = gate1_is_real(f)
    g2, n2 = gate2_in_scope(f, workspace, base)
    g3, n3 = gate3_exploitable(f, base, workspace)
    g4, n4 = gate4_not_dup(f, base)
    qs = questions(f, n2, base)
    gates = [
        {"n": 1, "name": "is_real", "pass": g1, "notes": n1},
        {"n": 2, "name": "in_scope", "pass": g2, "notes": n2},
        {"n": 3, "name": "exploitable", "pass": g3, "notes": n3},
        {"n": 4, "name": "not_dup", "pass": g4, "notes": n4},
    ]
    all_gates = all(g["pass"] for g in gates)
    all_q = all(q["pass"] for q in qs)
    status = "validated_finding" if (all_gates and all_q and not kills) else "scanner_hit"
    reasons = list(kills)
    for g in gates:
        if not g["pass"]:
            reasons.append(f"gate{g['n']}_{g['name']}: {g['notes'].get('reason', 'failed')}")
    for q in qs:
        if not q["pass"]:
            reasons.append(f"q{q['n']}: {q['question']}")

    payload = {
        "generated_at": config.iso(),
        "finding_id": _clean(f.get("id")),
        "status": status,
        "vuln_class": cls,
        "dup_key": n4["dup_key"],
        "gates": gates,
        "questions": qs,
        "kill_signals": kills,
        "rejection_reasons": [] if status == "validated_finding" else reasons,
        "finding": {k: f.get(k) for k in
                    ("id", "program", "target", "endpoint", "vuln_class", "impact", "summary")},
    }

    if write:
        f["status"] = status
        f["validated_at"] = config.iso() if status == "validated_finding" else f.get("validated_at")
        f["dup_key"] = n4["dup_key"]
        src = find_finding(_clean(f.get("id")), workspace, base)
        if src:
            save_finding(src, f)
            vpath = src.with_suffix(".validation.json")
            config.write_json(vpath, payload)
            payload["validation_path"] = str(vpath)
        if status == "validated_finding":
            entry = {
                "finding_id": _clean(f.get("id")), "program": _clean(f.get("program")),
                "target": _clean(f.get("target")), "endpoint": _clean(f.get("endpoint")),
                "vuln_class": cls, "dup_key": n4["dup_key"], "status": status,
                "validated_at": config.iso(), "impact": _clean(f.get("impact"))[:240],
            }
            if not any(e.get("finding_id") == entry["finding_id"] and e.get("dup_key") == entry["dup_key"]
                       for e in load_registry(base)):
                append_registry(entry, base)
            if workspace:
                _mark_validated(workspace, entry)
    return payload


def _mark_validated(workspace: Path, entry: dict) -> None:
    def _m(s):
        s.mark_milestone("validated-finding")
        findings = dict(s.extra.get("bb_findings", {}) or {})
        findings[entry["finding_id"]] = entry
        s.extra["bb_findings"] = findings
    try:
        statex.locked_update(workspace, _m)
    except Exception:
        pass


def validate_file(path: Path, *, workspace: Path | None = None,
                  base: Path | None = None, write: bool = True) -> dict:
    return validate(load_finding(path), workspace=workspace, base=base, write=write)


def render(payload: dict) -> str:
    lines = [f"finding: {payload.get('finding_id')}",
             f"status:  {payload.get('status')}", ""]
    lines.append("GATES")
    for g in payload.get("gates", []):
        lines.append(f"  {'PASS' if g['pass'] else 'FAIL'}  gate{g['n']} {g['name']}")
    lines.append("")
    lines.append("QUESTIONS")
    for q in payload.get("questions", []):
        lines.append(f"  {'PASS' if q['pass'] else 'FAIL'}  Q{q['n']} {q['question']}")
    if payload.get("kill_signals"):
        lines.append("")
        lines.append("KILL SIGNALS")
        lines += [f"  - {k}" for k in payload["kill_signals"]]
    if payload.get("rejection_reasons"):
        lines.append("")
        lines.append("REASONS")
        lines += [f"  - {r}" for r in payload["rejection_reasons"]]
    return "\n".join(lines)


def new_finding_skeleton(finding_id: str, *, program: str = "", target: str = "",
                         vuln_class: str = "", workspace: Path | None = None) -> dict:
    return {
        "id": finding_id, "program": program, "target": target,
        "endpoint": "", "vuln_class": vuln_class, "summary": "", "impact": "",
        "curl_poc": "", "evidence": [], "control_evidence": "",
        "reproduced": False, "deterministic": False, "not_documented": False,
        "identity_proven": False, "unrealistic_preconditions": False,
        "chain_proven": False, "skill_checked": False, "skills_used": [],
        "already_tried": False, "cheaper_test": "", "confirm_refute": "",
        "refute_plan": "", "status": "scanner_hit",
    }
