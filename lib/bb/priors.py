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
from lib.state import TargetState

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


PAYOUT_MAX = 0.25  # §3.2 tiebreaker multiplier cap at the top payout tier


def load_payouts(workspace: Path | None) -> dict[str, float]:
    """programs/<slug>/payouts.json: category -> expected payout amount.
    Purely advisory scoring signal; missing file = no adjustment."""
    if not workspace:
        return {}
    data = config.read_json(Path(workspace) / "payouts.json", default=None)
    if not isinstance(data, dict):
        return {}
    out = {}
    for k, v in data.items():
        try:
            out[str(k)] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def adjusted(state, priors: dict | None = None,
             bias: dict[str, dict] | None = None,
             payouts: dict[str, float] | None = None) -> list[dict]:
    """Ranked open hypotheses with prior-adjusted cost (does not mutate).

    `bias` maps category -> {mult, source, sim} from the similar-box
    fingerprint index (§2.1); matching categories get a modest score
    multiplier so hypotheses that worked on the most similar past box rise,
    without ever hiding the underlying confidence/cost math.

    `payouts` (§3.2) maps category -> expected bounty; equally-promising
    hypotheses get ordered by expected value as a tiebreaker, capped at
    PAYOUT_MAX so money never outweighs confidence/cost."""
    priors = priors or load_priors()
    max_payout = max(payouts.values()) if payouts else 0.0
    out = []
    for h in state.hypotheses.values():
        if h.status != "open":
            continue
        prior, category = suggest_cost(h, priors)
        cost = h.cost
        # only override the flat default, never a cost a human deliberately set
        if abs(float(h.cost) - float(priors.get("default_cost", DEFAULT_COST))) < 1e-9:
            cost = prior
        score = h.confidence / max(cost, 0.1)
        hint = ""
        b = (bias or {}).get(category)
        if b:
            score *= b["mult"]
            hint = f"← {b['source']} (sim {b['sim']:.2f})"
        amount = (payouts or {}).get(category)
        if amount and max_payout > 0:
            score *= 1.0 + PAYOUT_MAX * (amount / max_payout)
            hint = (hint + f" | ${amount:g}").strip(" |")
        out.append({
            "id": h.id, "statement": h.statement, "status": h.status,
            "confidence": h.confidence, "cost": h.cost, "prior_cost": prior,
            "effective_cost": cost, "category": category,
            "score": score, "sim_hint": hint,
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


# ---- §2.3 recurring recalibration ---------------------------------------

MIN_SAMPLES = 3      # a category needs this many decided hypotheses to refit
SHIFT = 0.5          # cost moves halfway toward the observed hit/miss imbalance
COST_MIN, COST_MAX = 0.2, 6.0


def refit(base: Path | None = None) -> dict:
    """Refit keyword costs against the accumulated workspace history.

    For each category: confirmation rate across every decided hypothesis in
    every workspace. High hit-rate categories get cheaper (tried earlier),
    low hit-rate categories get dearer — the priors drift toward what has
    actually been working as the solved-corpus grows."""
    base = base or config.root()
    pri = load_priors(base)
    base_costs = {e["category"]: float(e["cost"])
                  for e in pri.get("keyword_costs", [])}
    stats: dict[str, dict[str, int]] = {}
    for ws in config.discover_workspaces(base):
        try:
            state = TargetState.load(ws)
        except Exception:
            continue
        for h in state.hypotheses.values():
            if h.status not in ("confirmed", "refuted"):
                continue
            _cost, cat = suggest_cost(h, pri)
            if cat == "default":
                continue
            s = stats.setdefault(cat, {"confirmed": 0, "refuted": 0})
            s[h.status] += 1
    fitted, rows = {}, []
    for cat, base_cost in base_costs.items():
        s = stats.get(cat)
        if not s or s["confirmed"] + s["refuted"] < MIN_SAMPLES:
            continue
        n = s["confirmed"] + s["refuted"]
        hit_rate = s["confirmed"] / n
        new_cost = round(max(COST_MIN, min(COST_MAX,
                       base_cost * (1 + SHIFT * (1 - 2 * hit_rate)))), 2)
        fitted[cat] = {"base_cost": base_cost, "new_cost": new_cost,
                       "confirmed": s["confirmed"], "refuted": s["refuted"]}
        rows.append((cat, new_cost))
    if not rows:
        return {"changed": False, "reason": "not enough decided hypotheses "
                f"(need >= {MIN_SAMPLES} per category)", "fitted": fitted}
    by_cat = dict(rows)
    new_costs = []
    for e in pri.get("keyword_costs", []):
        entry = dict(e)
        if e["category"] in by_cat:
            entry["cost"] = by_cat[e["category"]]
        new_costs.append(entry)
    pri["keyword_costs"] = new_costs
    pri["generated_at"] = config.iso()
    pri["refit"] = {"at": config.iso(), "fitted": fitted}
    save_priors(pri, base=base)
    return {"changed": True, "fitted": fitted}


def runs_since_refit(base: Path | None = None) -> int:
    """Benchmark snapshots newer than the last priors generation (§2.3
    auto-trigger threshold check)."""
    base = base or config.root()
    pri = config.read_json(priors_path(base), default=None)
    if not pri or not pri.get("generated_at"):
        return 10**9
    try:
        import datetime
        gen = datetime.datetime.fromisoformat(pri["generated_at"]).timestamp()
    except (ValueError, TypeError):
        return 10**9
    n = 0
    for p in (base / "benchmark" / "runs").glob("*.json"):
        try:
            if p.stat().st_mtime > gen:
                n += 1
        except OSError:
            continue
    return n
