"""§1.7 coverage map — what has been enumerated vs what has not.

Dedup stops the same action repeating; coverage tracking stops an entire
area from never being noticed. Derived deterministically from the action
log (no model, no extra state to maintain): which hosts had port scans,
which had web content discovery, auth-state testing, AD enumeration, local
privesc sweeps, vuln-class probes. `gaps()` turns that into concrete
"this is missing" statements that next-hyp and recon-agent consume.
"""

from __future__ import annotations

import re
from pathlib import Path

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_HOST_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
_PORT_RE = re.compile(r"(?:-p(?:orts?)?|--top-ports)\s+([\d,\-]+|-p-)")
_ALLPORTS_RE = re.compile(r"-p-|-p\s*all|--top-ports\s+all", re.I)

_WEB_FUZZ_RE = re.compile(r"feroxbuster|gobuster|ffuf|dirb|dirsearch|ferox\b", re.I)
_AUTH_RE = re.compile(r"login|auth|spray|hydra|cred|password|jwt|session", re.I)
_AD_RE = re.compile(r"bloodhound|kerberoast|enum4linux|netexec|crackmapexec|"
                    r"impacket|GetUserSPNs|asrep|GetNPUsers|secretsdump", re.I)
_LOCAL_RE = re.compile(r"sudo\s+-l|getcap|perm\s*-?\s*4000|linpeas|linenum|"
                       r"pspy|SUID", re.I)
_VULN_RE = re.compile(r"nuclei|sqlmap|nikto|dalfox|\bsqli\b|\bssrf\b|\bssti\b|"
                      r"\bxxe\b|\bidor\b|\bxss\b", re.I)
_WEB_PORT_RE = re.compile(r"\b(80|443|8080|8443|8000|8888|4433)\b")


def _host_of(cmd: str) -> str:
    m = _IP_RE.search(cmd)
    if m:
        return m.group(1)
    m = _HOST_RE.search(cmd)
    if m:
        return m.group(1).lower()
    return "(global)"


def derive(state) -> dict:
    """Coverage facts from the action log. Keys are hosts ('(global)' for
    host-agnostic actions)."""
    cov = {
        "port_scan": {},      # host -> port specs scanned
        "web_fuzz": set(),    # hosts with content discovery
        "auth_test": set(),   # hosts with auth-state testing
        "ad_enum": set(),     # hosts with AD enumeration
        "local_enum": set(),  # local privesc sweeps (host = '(local)')
        "vuln_probe": {},     # host -> class tokens probed
    }
    for a in state.actions.values():
        cmd = a.command or ""
        host = _host_of(cmd)
        if re.search(r"nmap|masscan|rustscan", cmd, re.I):
            m = _ALLPORTS_RE.search(cmd)
            if m:
                cov["port_scan"].setdefault(host, set()).add("all")
            else:
                for pm in _PORT_RE.finditer(cmd):
                    cov["port_scan"].setdefault(host, set()).add(pm.group(1))
            if not _PORT_RE.search(cmd) and not _ALLPORTS_RE.search(cmd):
                cov["port_scan"].setdefault(host, set()).add("default")
        if _WEB_FUZZ_RE.search(cmd):
            cov["web_fuzz"].add(host)
        if _AUTH_RE.search(cmd):
            cov["auth_test"].add(host)
        if _AD_RE.search(cmd):
            cov["ad_enum"].add(host)
        if _LOCAL_RE.search(cmd):
            cov["local_enum"].add("(local)")
        vm = _VULN_RE.search(cmd)
        if vm:
            cov["vuln_probe"].setdefault(host, set()).add(vm.group(1).lower())
    return cov


def gaps(state) -> list[str]:
    """Concrete uncovered areas, most important first. Deterministic."""
    cov = derive(state)
    out: list[str] = []

    scanned_hosts = set(cov["port_scan"])
    if not scanned_hosts:
        out.append("no port scan recorded yet — run the recon bundle first")
        return out

    # web hosts seen in scan results / summaries but never content-discovered
    web_hosts = set()
    for a in state.actions.values():
        blob = f"{a.command} {a.result_summary}"
        if _WEB_PORT_RE.search(blob) and re.search(r"http|apache|nginx|iis|"
                                                   r"tomcat|web", blob, re.I):
            h = _host_of(a.command) if _IP_RE.search(a.command) else \
                _host_of(a.result_summary or "")
            if h != "(global)":
                web_hosts.add(h)
    for h in sorted(web_hosts - cov["web_fuzz"]):
        out.append(f"web content discovery missing on {h}")

    # AD signals but no AD enumeration
    ad_signal = any(re.search(r"\b(88|389|445|636|3268)/tcp", a.result_summary or "")
                    for a in state.actions.values())
    if ad_signal and not cov["ad_enum"]:
        out.append("AD services visible but no AD enumeration run")

    # content discovered but auth states never tested
    for h in sorted(cov["web_fuzz"] - cov["auth_test"]):
        if h != "(global)":
            out.append(f"auth states untested on {h}")

    # shell obtained but no local privesc sweep
    if "user" in state.milestones and not cov["local_enum"]:
        out.append("user shell obtained but no local privesc sweep recorded")

    # no vuln-class probing anywhere on web hosts
    if web_hosts and not cov["vuln_probe"]:
        out.append("no vuln-class probes (nuclei/sqli/xss/...) recorded yet")
    return out


def hint_block(workspace: Path, state) -> str:
    """Prompt block for the first turn: prioritize the gaps."""
    gs = gaps(state)
    if not gs:
        return ""
    lines = [f"  - {g}" for g in gs[:5]]
    return ("--- COVERAGE GAPS (prioritize these; do not re-enumerate "
            "covered areas) ---\n" + "\n".join(lines) + "\n")


def footer(state, limit: int = 3) -> str:
    gs = gaps(state)
    return f"coverage gaps: {'; '.join(gs[:limit])}" if gs else ""
