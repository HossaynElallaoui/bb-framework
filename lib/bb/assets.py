"""§3.1 continuous scope-aware asset diffing.

Bounty mode between runs: re-run lightweight recon (passive subdomain enum,
low-rate liveness probes), diff against the last known asset set, and flag
genuinely *new* attack surface. Every candidate is checked against the scope
policy before it is probed or stored — out-of-scope discoveries are counted
and dropped, never touched. Passive enumeration only queries third-party
data about in-scope domains; active probing honours the policy's rate ceiling
and concurrency cap.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from lib.bb import config, leads, scope

ASSETS_FILE = "assets.json"
GO_HTTPX = Path("/home/kali/go/bin/httpx")
DEFAULT_RATE = 12

_DOMAIN_RE = re.compile(r"(?:\*\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def assets_path(workspace: Path) -> Path:
    return Path(workspace) / ASSETS_FILE


def load(workspace: Path) -> dict:
    data = config.read_json(assets_path(workspace), default=None)
    if not isinstance(data, dict) or not isinstance(data.get("assets"), dict):
        return {"updated_at": None, "assets": {}}
    return data


def norm_host(host: str) -> str | None:
    host = str(host).strip().lower().rstrip(".")
    if not host or " " in host or "/" in host:
        return None
    return host if re.fullmatch(r"(?:[a-z0-9_-]+\.)+[a-z0-9-]+|\d{1,3}(?:\.\d{1,3}){3}",
                                host) else None


def norm_url(url: str) -> str | None:
    try:
        parts = urlsplit(str(url).strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = norm_host(parts.hostname)
    if not host:
        return None
    path = (parts.path or "/").rstrip("/") or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{path}"


def diff_records(old: dict, new: dict) -> dict:
    """Pure added/gone/unchanged computation on asset-key dicts."""
    old_keys, new_keys = set(old), set(new)
    return {
        "added": sorted(new_keys - old_keys),
        "gone": sorted(old_keys - new_keys),
        "unchanged": sorted(old_keys & new_keys),
    }


def _seed_domains(policy) -> list[str]:
    out: set[str] = set()
    for pat in policy.allow or []:
        m = _DOMAIN_RE.search(pat)
        if m:
            out.add(m.group(1).lower())
    return sorted(out)


def _amass_passive(domain: str, timeout: int = 300) -> list[str]:
    """Passive subdomain enum: third-party data sources only, no target traffic."""
    try:
        r = subprocess.run(["amass", "enum", "-passive", "-d", domain,
                            "-timeout", str(max(1, timeout // 60))],
                           capture_output=True, text=True, timeout=timeout)
        return [l.strip().lower() for l in (r.stdout or "").splitlines()
                if l.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def _httpx_probe(hosts: list[str], rate: int, conc: int,
                 timeout: int = 120) -> list[str]:
    """Liveness probe of already-scope-checked hosts at the agreed ceiling."""
    if not hosts:
        return []
    exe = str(GO_HTTPX) if GO_HTTPX.exists() else "httpx"
    try:
        r = subprocess.run(
            [exe, "-silent", "-json", "-rate", str(max(1, rate)),
             "-c", str(max(1, conc)), "-timeout", "10", "-no-color"],
            input="\n".join(hosts), capture_output=True, text=True,
            timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in (r.stdout or "").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            d = None
        if isinstance(d, dict) and d.get("url"):
            out.append(d["url"])
    return out


def scan(workspace: Path, base: Path | None = None, mode: str = "bounty",
         ingest_leads: bool = False) -> dict:
    base = base or config.root()
    workspace = Path(workspace)
    policy = scope.load_policy(workspace=workspace, mode=mode, base=base)
    if policy is None or not (policy.allow or []):
        raise ValueError("no scope policy / allow patterns — fill in scope.md "
                         "(assets diffing fails closed)")
    prev = load(workspace)
    old = prev.get("assets") or {}

    candidates: set[str] = set()
    rejected = 0
    for dom in _seed_domains(policy):
        candidates.add(dom)
        for host in _amass_passive(dom):
            candidates.add(host)
    for stored in old:
        candidates.add(stored)

    in_scope: list[str] = []
    for cand in sorted(candidates):
        host = norm_host(cand)
        if not host:
            continue
        verdict = policy.check(host)
        if verdict.get("in_scope"):
            in_scope.append(host)
        else:
            rejected += 1

    rate = policy.rate_per_min or DEFAULT_RATE
    conc = policy.max_concurrency or 1
    live_urls = _httpx_probe(in_scope, rate=rate, conc=conc)

    now = time.time()
    assets: dict[str, dict] = {}
    for key in old:
        rec = dict(old[key])
        rec["last_seen"] = rec.get("last_seen") or now  # refreshed below if reseen
        assets[key] = rec
    for host in in_scope:
        if host in assets:
            assets[host]["last_seen"] = now
        else:
            assets[host] = {"kind": "host", "first_seen": now, "last_seen": now,
                            "source": "amass-passive"}
    for url in (norm_url(u) for u in live_urls):
        if not url:
            continue
        if url in assets:
            assets[url]["last_seen"] = now
        else:
            assets[url] = {"kind": "url", "first_seen": now, "last_seen": now,
                           "source": "httpx"}

    d = diff_records(old, assets)
    payload = {"updated_at": now, "assets": assets}
    config.write_json(assets_path(workspace), payload)

    added_leads = 0
    if ingest_leads:
        for key in d["added"]:
            if leads.add(workspace, "recon-scan", key, signal="asset-diff",
                         priority="med"):
                added_leads += 1

    return {"added": d["added"], "gone": d["gone"],
            "total": len(assets), "rejected_out_of_scope": rejected,
            "added_leads": added_leads, "workspace": str(workspace)}


def show(workspace: Path) -> dict:
    data = load(workspace)
    assets = data.get("assets") or {}
    hosts = sorted(k for k, v in assets.items() if v.get("kind") == "host")
    urls = sorted(k for k, v in assets.items() if v.get("kind") == "url")
    return {"updated_at": data.get("updated_at"), "hosts": hosts, "urls": urls,
            "total": len(assets)}
