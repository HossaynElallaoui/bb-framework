"""Deterministic scope gate.

Two sources of truth are supported:

  programs/<slug>/scope.md   the human/agent-maintained program scope
  programs/<slug>/scope.env  hard machine config (allow/exclude/rate/header)
  programs/htb/*.json        HTB provider scope files (pre-authorized session)

The markdown parser is deliberately conservative: it only reads the
in-scope and exclusion sections, extracts host-shaped tokens from table
cells and backticks, and fails closed. Exclusions always win. A target with
no policy is DENY, never allow.

The actual matcher is the vendored upstream `ScopeChecker` (anchored suffix
matching, CIDR support, alternate-IP-encoding rejection). Parsing and
matching are kept separate so a parser change can never silently widen a
matcher rule.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from lib.bb import config
from lib.bb.scope_checker import ScopeChecker, ScopeError

HOST_RE = re.compile(
    r"(?<![\w.-])((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"
    r"(?::(\d{1,5}))?((?:/[^\s|`)\]\"'<>]*)?)",
    re.I,
)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")
BACKTICK_RE = re.compile(r"`([^`\n]{2,200})`")

# Never treat the platform's own rules page as an in-scope asset.
SKIP_HOSTS = {
    "yeswehack.com", "www.yeswehack.com", "hackerone.com", "www.hackerone.com",
    "bugcrowd.com", "www.bugcrowd.com", "intigriti.com", "www.intigriti.com",
    "app.hackthebox.com", "hackthebox.com", "www.hackthebox.com",
}
FILE_EXTS = {
    "md", "json", "csv", "txt", "py", "sh", "js", "html", "htm", "yaml", "yml",
    "png", "jpg", "jpeg", "pdf", "zip", "tar", "gz", "env", "example",
}

IN_SCOPE_HEADINGS = (
    "in-scope", "in scope", "active assets", "scope assets", "assets",
    "allowed assets", "applications", "targets",
)
EXCLUDE_HEADINGS = (
    "exclusion", "out-of-scope", "out of scope", "not in scope",
    "eligibility exclusion", "asset and product exclusion",
)


@dataclass
class Policy:
    program: str
    mode: str
    allow: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    excluded_classes: list[str] = field(default_factory=list)
    rate_per_min: float | None = None
    required_header: str | None = None
    max_concurrency: int | None = None
    sources: list[str] = field(default_factory=list)
    note: str = ""
    checker: ScopeChecker | None = None

    def __post_init__(self):
        try:
            self.checker = ScopeChecker(self.allow, self.exclude, self.excluded_classes)
        except ScopeError:
            # A dangerous pattern is a hard config error -> fail closed, but
            # keep the object inspectable so `scope-check --full` can explain.
            self.checker = ScopeChecker([], self.exclude, self.excluded_classes)
            self.note = (self.note + " | " if self.note else "") + \
                        "invalid allow pattern rejected; policy fails closed"

    def check(self, target: str) -> dict:
        verdict = self.checker.explain(target) if self.checker else {
            "in_scope": False, "reason": "no checker", "matched_rule": None,
            "host": None, "kind": "invalid",
        }
        verdict["program"] = self.program
        verdict["mode"] = self.mode
        return verdict


def _headings(text: str) -> list[tuple[int, str, int, int]]:
    """(level, title, start, end_of_heading_line) for every ATX heading."""
    out = []
    for m in re.finditer(r"(?m)^(#{1,6})\s+(.+?)\s*$", text):
        out.append((len(m.group(1)), m.group(2).strip(), m.start(), m.end()))
    return out


def _section(text: str, keywords: tuple[str, ...], max_level: int = 2,
             avoid: tuple[str, ...] = ()) -> str:
    """Concatenate text under headings whose title contains a keyword.

    `avoid` lets the in-scope scan skip headings that also look like
    exclusions ("Out-of-scope assets", "Assets we do not cover"). Exclusions
    still win in the matcher, but keeping them out of the allow list makes
    `--full` honest and reduces accidental widening.
    """
    hs = _headings(text)
    chunks = []
    for i, (level, title, _start, end) in enumerate(hs):
        if level > max_level:
            continue
        low = title.lower()
        if any(k in low for k in avoid):
            continue
        if not any(k in low for k in keywords):
            continue
        # section runs to the next heading of level <= this level (or EOF)
        stop = len(text)
        for lvl, _t, start, _e in hs[i + 1:]:
            if lvl <= level:
                stop = start
                break
        chunks.append(text[end:stop])
    return "\n".join(chunks)


def _clean_candidate(raw: str) -> str | None:
    s = raw.strip().strip("`'\"<>()[].,;:")
    s = re.sub(r"^[a-z]+://", "", s, flags=re.I)
    s = s.split("#", 1)[0].strip()
    if not s or " " in s or "\t" in s:
        return None
    # Template placeholders in a path (:folder:, {id}, <x>) are documentation,
    # not hosts. Treat the whole token as unusable rather than widening it to a
    # host-level exclusion.
    if any(ch in s for ch in "{}<>"):
        return None
    if "/" in s and ":" in s.split("/", 1)[1]:
        return None
    # drop a trailing /* (path wildcard) but keep the directory prefix
    s = re.sub(r"/\*+$", "/", s)
    s = re.sub(r"(?<=[^/])\*+$", "", s)
    host_part = s.split("/", 1)[0]
    if host_part.startswith("*."):
        base = host_part[2:]
        if not base or "*" in base:
            return None
    else:
        if "*" in host_part:
            return None
    # IP / CIDR passes straight through
    try:
        ipaddress.ip_network(host_part, strict=False)
        return s
    except ValueError:
        pass
    last = host_part.rsplit(".", 1)[-1].lower()
    if last in FILE_EXTS:
        return None
    if host_part.lower() in SKIP_HOSTS:
        return None
    return s


def extract_patterns(text: str) -> list[str]:
    """All host/URL-shaped patterns in a section, order-preserved, deduped."""
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str):
        c = _clean_candidate(raw)
        if not c:
            return
        key = c.lower().rstrip("/")
        if key and key not in seen:
            seen.add(key)
            found.append(c)

    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.strip().startswith("|") else []
        scan = cells if cells else [line]
        for cell in scan:
            # backticked tokens are the author's explicit intent
            for bt in BACKTICK_RE.findall(cell):
                for m in HOST_RE.finditer(bt):
                    add(m.group(0))
                for m in IP_RE.finditer(bt):
                    add(m.group(0))
            if cells:
                # table cells: scan the whole cell (contains asset lists)
                for m in HOST_RE.finditer(cell):
                    add(m.group(0))
                for m in IP_RE.finditer(cell):
                    add(m.group(0))
            else:
                # prose: only backticks, to avoid grabbing unrelated domains
                continue
    return found


def _parse_env(path: Path) -> dict:
    out: dict = {}
    try:
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip().upper()] = v.strip().strip("'\"")
    except OSError:
        pass
    return out


def _split(v: str | None) -> list[str]:
    if not v:
        return []
    return [p.strip() for p in re.split(r"[,\s]+", v) if p.strip()]


def _rate_from_text(text: str) -> tuple[float | None, str]:
    low = text.lower()
    m = re.search(r"(\d+(?:\.\d+)?)\s*(?:req(?:uest)?s?\s*)?(?:/|per\s*)\s*(second|sec|minute|min)", low)
    if m:
        n = float(m.group(1))
        unit = m.group(2)
        if unit.startswith("sec"):
            return n * 60.0, f"{n}/s from scope text"
        return n, f"{n}/min from scope text"
    if "single" in low and "sequential" in low:
        return 12.0, "no numeric limit; conservative 12/min (sequential) default"
    if "no automated" in low or "no automated scanners" in low:
        return 6.0, "automation restricted; conservative 6/min default"
    return None, ""


def _required_header(text: str) -> str | None:
    m = re.search(r"required[^\n]{0,40}header[^\n]{0,10}[:`]\s*`?([^`\n]+)`?", text, re.I)
    return m.group(1).strip() if m else None


def load_policy(*, program: str | None = None, workspace: Path | str | None = None,
                mode: str = "bounty", target: str | None = None,
                base: Path | None = None) -> Policy | None:
    base = base or config.root()
    ws = Path(workspace) if workspace else None
    if ws and not ws.is_absolute():
        ws = base / ws

    # 1) workspace-owned policy (bounty program dir)
    candidates: list[Path] = []
    if ws and ws.is_dir():
        candidates.append(ws)
    if program:
        candidates.append(base / "programs" / program)

    for d in candidates:
        md = d / "scope.md"
        env = d / "scope.env"
        if not md.exists() and not env.exists():
            continue
        text = md.read_text(errors="ignore") if md.exists() else ""
        allow = extract_patterns(_section(
            text, IN_SCOPE_HEADINGS,
            avoid=EXCLUDE_HEADINGS + ("not eligible", "do not", "don't", "not covered",
                                      "non-scope")))
        if not allow and not _headings(text):
            allow = extract_patterns(text)  # headingless doc: best-effort scan
        exclude = extract_patterns(_section(text, EXCLUDE_HEADINGS))
        e = _parse_env(env)
        allow = _split(e.get("BB_ALLOW")) or allow
        exclude = _split(e.get("BB_EXCLUDE")) or exclude
        excluded_classes = _split(e.get("BB_EXCLUDED_CLASSES"))
        rate, rate_note = _rate_from_text(text)
        if e.get("BB_RATE_PER_MIN"):
            try:
                rate = float(e["BB_RATE_PER_MIN"])
                rate_note = "scope.env BB_RATE_PER_MIN"
            except ValueError:
                pass
        sources = [str(p.relative_to(base)) for p in (md, env) if p.exists()]
        return Policy(
            program=d.name, mode=mode, allow=allow, exclude=exclude,
            excluded_classes=excluded_classes, rate_per_min=rate,
            required_header=e.get("BB_REQUIRED_HEADER") or _required_header(text),
            max_concurrency=int(e["BB_MAX_CONCURRENCY"]) if e.get("BB_MAX_CONCURRENCY", "").isdigit() else None,
            sources=sources, note=rate_note,
        )

    # 2) HTB provider scope
    if mode == "htb":
        name = program or (ws.name if ws else None)
        for js in sorted((base / "programs" / "htb").glob("*.json")):
            data = config.read_json(js, default={}) or {}
            hosts = (data.get("scope") or {}).get("hosts", [])
            if not hosts:
                continue
            if (name and (data.get("name", "").lower() == name.lower()
                          or js.stem.lower() == name.lower())) or (target and target in hosts):
                return Policy(program=js.stem, mode="htb", allow=list(hosts),
                              sources=[str(js.relative_to(base))],
                              note="HTB lab machine - pre-authorized for this VPN session")
        # HTB target without a staged json: pre-authorized, literal host only
        if target and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target):
            return Policy(program=name or "htb", mode="htb", allow=[target],
                          sources=[], note="HTB lab target (literal host, no json staged)")

    return None


def check_target(target: str, *, program: str | None = None,
                 workspace: Path | str | None = None, mode: str = "bounty",
                 base: Path | None = None) -> tuple[bool, dict]:
    policy = load_policy(program=program, workspace=workspace, mode=mode,
                         target=target, base=base)
    if policy is None:
        return False, {
            "in_scope": False, "program": program, "mode": mode,
            "target": target, "matched_rule": None,
            "reason": "no scope policy found — failing closed (load programs/<slug>/scope.md "
                      "or pass --program/--workspace)",
        }
    verdict = policy.check(target)
    verdict["target"] = target
    verdict["sources"] = policy.sources
    return bool(verdict["in_scope"]), verdict


def enumerate_policy(policy: Policy) -> dict:
    return {
        "program": policy.program,
        "mode": policy.mode,
        "allow": policy.allow,
        "exclude": policy.exclude,
        "excluded_classes": policy.excluded_classes,
        "rate_per_min": policy.rate_per_min,
        "required_header": policy.required_header,
        "max_concurrency": policy.max_concurrency,
        "sources": policy.sources,
        "note": policy.note,
    }
