"""Persistent recon -> hunt-* lead ledger, workspace-scoped.

Port of upstream `tools/lead_board.py` (the "hunter focuses on one lead; the
board remembers the rest" pattern), with two deliberate changes:

  * storage lives in `<workspace>/leads.jsonl`, not a global memory dir, so a
    scope-gated run cannot leak another program's leads;
  * writes use the same flock + atomic-replace discipline as state.py.

Discovery and verification stay separate: a lead is a routing hint, not a
finding. Only `bb validate` can promote it.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

P_HIGH, P_MED, P_LOW = "high", "med", "low"
PRIO_RANK = {P_HIGH: 0, P_MED: 1, P_LOW: 2}
HIGH_VALUE = {"hunt-idor", "hunt-graphql", "hunt-ssrf", "hunt-llm-ai",
              "hunt-source-leak", "hunt-oauth", "hunt-ato", "hunt-auth-bypass"}
STATUSES = ("new", "investigating", "killed", "reported", "parked")

R = re.compile
ROUTES = [
    (R(r"[?&](url|uri|dest|destination|callback|fetch|proxy|feed|host|image_url)=", re.I),
     "hunt-ssrf", P_HIGH, "URL-valued param", "server may fetch attacker URL -> SSRF/IMDS"),
    (R(r"[?&](next|redirect|redirect_uri|return|returnurl|continue|goto|checkout_url|success_url)=", re.I),
     "hunt-open-redirect", P_MED, "redirect param", "open redirect; chains to OAuth token theft"),
    (R(r"[?&](id|uid|user_id|account|account_id|order|order_id|invoice|doc_id|file_id|record|profile|customer)=\d", re.I),
     "hunt-idor", P_HIGH, "numeric object ref", "sequential ID -> IDOR/BOLA; swap tenant"),
    (R(r"/graph(i?ql|iql)|/api/graphql|/gql\b", re.I),
     "hunt-graphql", P_HIGH, "GraphQL endpoint", "introspection/batching/alias-IDOR"),
    (R(r"upload|/files?/|attachment|avatar|/media/upload|presign", re.I),
     "hunt-file-upload", P_HIGH, "upload surface", "unrestricted upload -> stored XSS/RCE/SSRF"),
    (R(r"[?&](q|s|search|query|keyword|term|name|comment|message|content|text)=", re.I),
     "hunt-xss", P_MED, "reflected text param", "reflected XSS candidate; check CSP"),
    (R(r"[?&](q|search|filter|sort|order|orderby|where|category|type|status)=", re.I),
     "hunt-sqli", P_MED, "query/filter param", "SQLi/NoSQLi candidate on data param"),
    (R(r"[?&](file|page|path|template|include|view|doc|folder|lang|locale|theme)=", re.I),
     "hunt-lfi", P_MED, "path-valued param", "LFI/path-traversal; chain to source disclosure"),
    (R(r"[?&](template|tpl|preview|render|greeting|msg)=", re.I),
     "hunt-ssti", P_LOW, "template-ish param", "SSTI if server-side templating reflects it"),
    (R(r"/(login|signin|sign-in|auth|sso|oauth|authorize|connect|openid)\b|response_type=|client_id=", re.I),
     "hunt-oauth", P_HIGH, "OAuth/SSO flow", "redirect_uri validation, state, PKCE, code leak"),
    (R(r"saml|SAMLResponse|/saml2?\b|/acs\b", re.I),
     "hunt-saml", P_HIGH, "SAML endpoint", "signature wrapping / XSW / IdP confusion"),
    (R(r"/(admin|manage|console|dashboard|actuator|debug|staff|backoffice|wp-admin)(?:[/?]|$)", re.I),
     "hunt-auth-bypass", P_HIGH, "privileged path", "forced-browse / auth bypass to admin"),
    (R(r"reset|forgot|recover|/verify|/otp|2fa|/mfa|change.?email|change.?phone|change.?password", re.I),
     "hunt-ato", P_HIGH, "account-recovery flow", "ATO via reset/OTP/email-change weakness"),
    (R(r"wss?://|/ws\b|/socket|/cable|/live\b|/realtime|sockjs", re.I),
     "hunt-websocket", P_MED, "WebSocket", "cross-site WS hijack, origin check, auth-over-WS"),
    (R(r"\.git\b|/\.env\b|\.svn|\.map(\?|$)|/backup|\.bak\b|\.old\b|\.sql(\?|$)|\.zip(\?|$)", re.I),
     "hunt-source-leak", P_HIGH, "exposed source/artifact", "source map / .git / backup -> secrets"),
    (R(r"/(chat|completions|assistant|copilot|llm|ai|embeddings|generate)\b|/v1/(chat|messages)|/mcp\b", re.I),
     "hunt-llm-ai", P_HIGH, "AI/LLM endpoint", "prompt-injection/exfil -> ai surface"),
    (R(r"asp\.net|iis|\.aspx|aspxauth|__viewstate", re.I),
     "hunt-aspnet", P_MED, "ASP.NET/IIS", "ViewState deser, padding-oracle, path tricks"),
    (R(r"laravel|symfony|laravel_session|x-powered-by:.*php", re.I),
     "hunt-laravel", P_MED, "Laravel/PHP", "debug mode, APP_KEY deser, .env leak"),
    (R(r"spring|spring-?boot|actuator|tomcat|jsessionid", re.I),
     "hunt-springboot", P_MED, "Spring/Java", "actuator exposure, SpEL, deser gadgets"),
    (R(r"next\.?js|_next/|__next_data__", re.I),
     "hunt-nextjs", P_MED, "Next.js", "SSRF via image opt, middleware authz, data leak"),
    (R(r"kubernetes|kubelet|kube|:10250|:6443|/api/v1/namespaces", re.I),
     "hunt-k8s", P_HIGH, "Kubernetes", "exposed kubelet/api, anon RBAC, etcd"),
    (R(r"firebase|firestore|firebaseio|\.web\.app|\.firebaseapp", re.I),
     "hunt-cloud-misconfig", P_HIGH, "Firebase", "open Firestore rules, takeover, config leak"),
    (R(r"s3\.amazonaws|s3-|\.s3\.|blob\.core\.windows|storage\.googleapis", re.I),
     "hunt-cloud-misconfig", P_HIGH, "cloud bucket", "public read/write, listable, takeover"),
    (R(r"www-authenticate:\s*ntlm|\bntlm\b", re.I),
     "hunt-ntlm-info", P_LOW, "NTLM endpoint", "internal name/version leak via NTLM type-2"),
    (R(r"nginx|apache|haproxy|envoy|varnish|cloudflare|fastly", re.I),
     "hunt-http-smuggling", P_LOW, "proxy/CDN chain", "CL.TE/TE.CL desync if origin disagrees"),
    (R(r".+"), "hunt-rce", P_HIGH, "nuclei finding", "confirmed by nuclei — verify + weaponize"),
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(workspace: Path) -> Path:
    return Path(workspace) / "leads.jsonl"


@contextmanager
def _lock(workspace: Path):
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    with open(workspace / ".leads.lock", "a") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def load(workspace: Path) -> list[dict]:
    out = []
    p = ledger_path(workspace)
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


def save(workspace: Path, leads: list[dict]) -> None:
    p = ledger_path(workspace)
    tmp = p.with_suffix(".jsonl.tmp")
    with open(tmp, "w") as fh:
        for ld in leads:
            fh.write(json.dumps(ld, ensure_ascii=False) + "\n")
    os.replace(tmp, p)


def norm_evidence(e: str) -> str:
    return re.sub(r"#.*$", "", (e or "").strip())[:300]


def dedup_key(skill: str, evidence: str) -> tuple[str, str]:
    return (skill or "", norm_evidence(evidence))


def adjudicate(lead: dict) -> tuple[bool, str]:
    if not isinstance(lead, dict):
        return False, "not a dict"
    if not str(lead.get("skill", "")).startswith("hunt-"):
        return False, "missing/invalid hunt-* skill"
    if len(norm_evidence(lead.get("evidence", ""))) < 3:
        return False, "evidence too short"
    if lead.get("priority") not in (P_HIGH, P_MED, P_LOW):
        return False, "invalid priority"
    return True, ""


def rank_key(ld: dict):
    return (PRIO_RANK.get(ld.get("priority"), 3),
            0 if ld.get("skill") in HIGH_VALUE else 1,
            ld.get("created", ""))


def route(text: str):
    for pat, skill, prio, label, why in ROUTES:
        if pat.search(text or ""):
            yield skill, prio, label, why


def _read_lines(path: Path) -> list[str]:
    try:
        return [l.strip() for l in path.read_text(errors="replace").splitlines()
                if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        return []


def gather_recon(recon_dir: Path) -> dict:
    urls, hosts, nuclei = [], [], []
    for pat in ("urls/all.txt", "urls/with_params.txt", "urls/api_endpoints.txt",
                "urls/js_files.txt", "js/endpoints.txt", "urls.txt", "**/urls.txt"):
        for f in recon_dir.glob(pat):
            if f.is_file():
                urls += _read_lines(f)
    for pat in ("live/httpx_full.txt", "live/urls.txt", "live-hosts.txt",
                "technologies.txt", "**/httpx_full.txt"):
        for f in recon_dir.glob(pat):
            if f.is_file():
                hosts += _read_lines(f)
    for pat in ("nuclei.txt", "nuclei/*.txt", "**/nuclei.txt"):
        for f in recon_dir.glob(pat):
            if f.is_file():
                nuclei += _read_lines(f)
    return {"urls": sorted(set(urls)), "hosts": sorted(set(hosts)),
            "nuclei": sorted(set(nuclei))}


def ingest(workspace: Path, recon_dir: Path) -> dict:
    rec = gather_recon(Path(recon_dir))
    added = updated = rejected = 0
    with _lock(workspace):
        leads = load(workspace)
        index = {dedup_key(l.get("skill", ""), l.get("evidence", "")): l for l in leads}

        def upsert(skill, prio, label, why, evidence, source):
            nonlocal added, updated, rejected
            key = dedup_key(skill, evidence)
            if key in index:
                index[key]["last_seen"] = _now()
                index[key]["seen_count"] = int(index[key].get("seen_count", 1)) + 1
                updated += 1
                return
            ld = {
                "id": "lb-" + secrets.token_hex(3), "skill": skill, "priority": prio,
                "signal": label, "why": why, "evidence": norm_evidence(evidence),
                "source": source, "status": "new", "note": "",
                "created": _now(), "last_seen": _now(), "seen_count": 1,
            }
            ok, _ = adjudicate(ld)
            if not ok:
                rejected += 1
                return
            leads.append(ld)
            index[key] = ld
            added += 1

        for u in rec["urls"]:
            for skill, prio, label, why in route(u):
                upsert(skill, prio, label, why, u, "url")
        for line in rec["hosts"]:
            for skill, prio, label, why in route(line):
                m = re.search(r"https?://[^\s\]]+", line)
                upsert(skill, prio, label, why, m.group(0) if m else line[:120], "tech")
        for n in rec["nuclei"]:
            for skill, prio, label, why in route(n):
                upsert(skill, prio, label, why, n[:200], "nuclei")
        save(workspace, leads)
    return {"added": added, "updated": updated, "rejected": rejected,
            "total": len(leads), "ledger": str(ledger_path(workspace))}


def add(workspace: Path, skill: str, evidence: str, signal: str = "",
        priority: str = P_MED, finding_id: str | None = None) -> dict | None:
    with _lock(workspace):
        leads = load(workspace)
        if any(dedup_key(l.get("skill", ""), l.get("evidence", "")) ==
               dedup_key(skill, evidence) for l in leads):
            return None
        ld = {"id": "lb-" + secrets.token_hex(3), "skill": skill, "priority": priority,
              "signal": signal or "manual", "why": "manually added",
              "evidence": norm_evidence(evidence), "source": "manual", "status": "new",
              "note": "", "created": _now(), "last_seen": _now(), "seen_count": 1}
        ok, _ = adjudicate(ld)
        if not ok:
            return None
        if finding_id:
            ld["finding_id"] = finding_id
        leads.append(ld)
        save(workspace, leads)
    return ld


def next_lead(workspace: Path) -> dict | None:
    leads = [l for l in load(workspace) if l.get("status") == "new"]
    return sorted(leads, key=rank_key)[0] if leads else None


def touch(workspace: Path, lead_id: str, status: str | None = None,
          note: str | None = None, finding_id: str | None = None) -> dict | None:
    with _lock(workspace):
        leads = load(workspace)
        hit = None
        for l in leads:
            if l.get("id") == lead_id:
                if status:
                    l["status"] = status
                if note is not None:
                    l["note"] = note
                if finding_id:
                    l["finding_id"] = finding_id
                l["updated"] = _now()
                hit = l
        if hit:
            save(workspace, leads)
    return hit


def claim(workspace: Path, lead_id: str, note: str | None = None) -> dict | None:
    return touch(workspace, lead_id, status="investigating", note=note)


def counts(workspace: Path) -> dict:
    out: dict[str, int] = {}
    for l in load(workspace):
        out[l.get("status", "?")] = out.get(l.get("status", "?"), 0) + 1
    return out
