"""Calibrated hypothesis costs and stall thresholds.

`state.next_hypothesis()` is deliberately a flat confidence/cost ratio; its
weakness is that free models assign every hypothesis cost=1.0. We keep the
ranking function unchanged (deterministic, cheap) but supply better priors
derived from the saved benchmark runs — the Connected run (23 actions, 1 dead
end, root in 567s) is the target profile, Autopilot (196 actions, 26 dead
ends) is the anti-pattern.
"""

from __future__ import annotations

import re
from pathlib import Path

from lib.bb import config

PRIORS_PATH = Path(__file__).with_name("priors.json")

DEFAULT_KEYWORDS: list[tuple[str, float, str]] = [
    (r"writeup|report|document", 0.2, "documentation"),
    (r"recon|nmap|ffuf|gobuster|subdomain|scan|httpx|curl|http\s+(get|request)", 0.6, "recon-scan"),
    (r"login|auth|session|cookie|token|jwt|oauth|saml|sso", 1.2, "auth-flow"),
    (r"idor|bola|object|tenant|ownership|cross-account|account_id", 1.5, "authz-comparison"),
    (r"upload|deserial|ssti|ssrf|xxe|sqli|rce|injection|smuggling|race", 2.0, "exploit"),
    (r"sudo|suid|capab|systemd|cron|incron|service|privilege|root|privesc", 2.5, "privesc"),
    (r"kerberos|kerberoast|asrep|dcsync|bloodhound|acl|adcs|ldap|smb|ntlm|relay", 3.0, "ad"),
    (r"brute|spray|wordlist|password", 4.0, "brute-force"),
]
DEFAULT_COST = 1.0


def _runs(base: Path) -> list[dict]:
    out = []
    for p in sorted((base / "benchmark" / "runs").glob("*.json")):
        d = config.read_json(p, default={})
        if isinstance(d, dict):
            d["_file"] = p.name
            out.append(d)
    return out


def derive(base: Path | None = None) -> dict:
    base = base or config.root()
    runs = _runs(base)
    successful = [r for r in runs if r.get("time_to_root_s") or r.get("time_to_flag_s")]
    pathological = [r for r in runs if (r.get("unique_actions") or 0) >= 150]
    # The operator's stated target profile is the Connected run (23 actions,
    # 1 dead end, root in 567s). Prefer it explicitly; otherwise choose the
    # successful run with the lowest action count (then fastest root).
    preferred = [r for r in successful
                 if "connected" in str(r.get("_file", "")).lower()]
    if preferred:
        best = preferred[0]
    else:
        best = min(successful, key=lambda r: (
            r.get("unique_actions") or 10**9,
            r.get("time_to_root_s") or r.get("time_to_flag_s") or 10**12,
        )) if successful else None
    worst = max(pathological, key=lambda r: r.get("unique_actions") or 0) if pathological else None

    best_actions = (best or {}).get("unique_actions") or 23
    threshold = max(20, int(best_actions * 2.5))
    return {
        "generated_at": config.iso(),
        "source_runs": [r.get("_file") for r in runs],
        "calibration": {
            "best_run": (best or {}).get("_file"),
            "best_actions": (best or {}).get("unique_actions"),
            "best_dead_ends": (best or {}).get("dead_ends"),
            "worst_run": (worst or {}).get("_file"),
            "worst_actions": (worst or {}).get("unique_actions"),
            "worst_dead_ends": (worst or {}).get("dead_ends"),
        },
        "stall": {
            "actions_threshold": threshold,
            "dead_end_rate": 0.25,
            "min_actions": 20,
        },
        "default_cost": DEFAULT_COST,
        "keyword_costs": [
            {"pattern": pat, "cost": cost, "category": cat}
            for pat, cost, cat in DEFAULT_KEYWORDS
        ],
    }


def priors_path(base: Path | None = None) -> Path:
    if base:
        return Path(base) / "lib" / "bb" / "priors.json"
    return PRIORS_PATH


def save_priors(data: dict, path: Path | None = None,
                base: Path | None = None) -> Path:
    path = path or priors_path(base)
    config.write_json(path, data)
    return path


def load_priors(base: Path | None = None) -> dict:
    path = priors_path(base)
    data = config.read_json(path, default=None)
    if not data or not isinstance(data, dict):
        data = derive(base)
        try:
            save_priors(data, path=path)
        except OSError:
            pass
    return data


def suggest_cost(hyp, priors: dict | None = None) -> tuple[float, str]:
    priors = priors or load_priors()
    text = " ".join([
        getattr(hyp, "statement", "") or "",
        getattr(hyp, "test", "") or "",
        getattr(hyp, "evidence", "") or "",
    ]).lower()
    for entry in priors.get("keyword_costs", []):
        try:
            if re.search(entry["pattern"], text, re.I):
                return float(entry["cost"]), entry.get("category", "")
        except re.error:
            continue
    return float(priors.get("default_cost", DEFAULT_COST)), "default"


def adjusted(state, priors: dict | None = None) -> list[dict]:
    """Ranked open hypotheses with prior-adjusted cost (does not mutate)."""
    priors = priors or load_priors()
    out = []
    for h in state.hypotheses.values():
        if h.status != "open":
            continue
        prior, category = suggest_cost(h, priors)
        cost = h.cost
        # only override the flat default, never a cost a human deliberately set
        if abs(float(h.cost) - float(priors.get("default_cost", DEFAULT_COST))) < 1e-9:
            cost = prior
        out.append({
            "id": h.id, "statement": h.statement, "status": h.status,
            "confidence": h.confidence, "cost": h.cost, "prior_cost": prior,
            "effective_cost": cost, "category": category,
            "score": h.confidence / max(cost, 0.1),
            "test": h.test, "evidence": h.evidence,
        })
    out.sort(key=lambda d: d["score"], reverse=True)
    return out


def apply_to_state(state, priors: dict | None = None) -> list[dict]:
    """Mutate flat-default hypothesis costs to calibrated priors. Returns
    the changed (id, old, new, category) rows."""
    priors = priors or load_priors()
    changed = []
    flat = float(priors.get("default_cost", DEFAULT_COST))
    for h in state.hypotheses.values():
        if h.status != "open" or abs(float(h.cost) - flat) > 1e-9:
            continue
        prior, category = suggest_cost(h, priors)
        if abs(prior - flat) > 1e-9:
            changed.append({"id": h.id, "old": h.cost, "new": prior, "category": category})
            h.cost = prior
    return changed
