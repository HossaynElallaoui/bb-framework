"""§2.1 similar-box technique retrieval.

A lightweight fingerprint index over past HTB workspaces: (open ports,
services, product banners, OS family) + the hypothesis categories that
actually confirmed, per machine. On a new box the early recon output is
compared against this index with weighted Jaccard — no embeddings — and
`next-hyp` biases hypothesis categories that worked on the most similar
solved boxes. Every solved machine becomes retrieval signal for the next one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from lib.bb import config, priors
from lib.state import TargetState

NMAP_GLOB = "nmap*.txt"
OS_KEYWORDS = (
    "windows", "ubuntu", "debian", "centos", "freebsd", "fedora", "redhat",
    "rhel", "samba", "kali", "rocky", "alpine", "arch",
)
# product tokens too generic to be useful fingerprints
_PRODUCT_STOP = {"protocol", "the", "and", "for", "version", "build"}

_NMAP_LINE = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?", re.I)


def _norm_service(svc: str) -> set[str]:
    """'ssl/https' -> {'ssl', 'https'}; keep the raw form too."""
    out = {svc.lower()}
    for part in svc.lower().split("/"):
        if part:
            out.add(part)
    return out


def _product_token(version: str) -> set[str]:
    """First product token of an nmap VERSION field, e.g. 'Apache/2.4.6 (CentOS)...'
    -> {'apache'}; 'OpenSSH 7.4' -> {'openssh'}."""
    out: set[str] = set()
    head = version.split("(")[0]
    for tok in re.split(r"[\s/,]+", head):
        tok = tok.strip().lower().strip(".")
        tok = re.sub(r"v?\d+(\.\d+)*$", "", tok).strip(".-")
        if len(tok) >= 3 and tok not in _PRODUCT_STOP and not tok.isdigit():
            out.add(tok)
            break  # first meaningful token only: banners are noisy
    return out


def parse_nmap(workspace: Path) -> dict[str, set[str]]:
    """Extract (ports, services, products, os) from nmap*.txt in a workspace."""
    ports: set[str] = set()
    services: set[str] = set()
    products: set[str] = set()
    os_hits: set[str] = set()
    text_parts: list[str] = []
    for p in sorted(Path(workspace).glob(NMAP_GLOB)):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        text_parts.append(text)
        for line in text.splitlines():
            m = _NMAP_LINE.match(line.strip())
            if not m:
                continue
            port, _proto, svc, version = m.groups()
            ports.add(f"{port}/{_proto}")
            services |= _norm_service(svc)
            if version:
                products |= _product_token(version)
    blob = "\n".join(text_parts).lower()
    for kw in OS_KEYWORDS:
        if kw in blob:
            os_hits.add(kw)
    return {"ports": ports, "services": services, "products": products,
            "os": os_hits}


def build_record(workspace: Path, base: Path | None = None) -> dict | None:
    """Fingerprint one workspace; None when there is nothing matchable."""
    base = base or config.root()
    workspace = Path(workspace)
    try:
        state = TargetState.load(workspace)
    except Exception:
        return None
    fp = parse_nmap(workspace)
    if not fp["ports"] and not fp["services"]:
        return None
    cats: set[str] = set()
    for h in state.hypotheses.values():
        if h.status == "confirmed":
            _cost, cat = priors.suggest_cost(h)
            if cat and cat != "default":
                cats.add(cat)
    solved = any(m in state.milestones for m in ("root", "flag", "validated-finding"))
    root_s = state.milestones.get("root") or state.milestones.get("flag")
    return {
        "machine": workspace.name,
        "solved": solved,
        "ports": sorted(fp["ports"]),
        "services": sorted(fp["services"]),
        "products": sorted(fp["products"]),
        "os": sorted(fp["os"]),
        "confirmed_categories": sorted(cats),
        "actions": len(state.actions),
        "root_s": round(root_s, 1) if root_s else None,
        "built_at": config.iso(),
    }


def index_dir(base: Path | None = None) -> Path:
    return (base or config.root()) / "benchmark" / "fingerprints"


def rebuild_index(base: Path | None = None) -> list[dict]:
    """Scan labs/HTB/machines/* workspaces and (re)write fingerprint records."""
    base = base or config.root()
    out: list[dict] = []
    root = base / "labs" / "HTB" / "machines"
    if not root.is_dir():
        return out
    for ws in sorted(root.iterdir()):
        if not (ws / "state.json").exists():
            continue
        rec = build_record(ws, base)
        if not rec:
            continue
        config.write_json(index_dir(base) / f"{rec['machine'].lower()}.json", rec)
        out.append(rec)
    return out


def load_index(base: Path | None = None) -> list[dict]:
    base = base or config.root()
    recs = []
    for p in sorted(index_dir(base).glob("*.json")):
        d = config.read_json(p, default=None)
        if isinstance(d, dict):
            recs.append(d)
    return recs


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return -1.0  # absent component: excluded from the weighted mean
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# component weights: ports/services identify the box, products refine, os is weak
_WEIGHTS = (("ports", 0.40), ("services", 0.30), ("products", 0.20), ("os", 0.10))


def similarity(query: dict, record: dict) -> float:
    """Weighted mean of per-component Jaccards over the non-absent components."""
    num = 0.0
    den = 0.0
    for key, w in _WEIGHTS:
        j = _jaccard(set(query.get(key) or []), set(record.get(key) or []))
        if j < 0:
            continue
        num += w * j
        den += w
    return round(num / den, 4) if den else 0.0


def rank(query: dict, base: Path | None = None, top: int = 3,
         solved_only: bool = True, min_sim: float = 0.05) -> list[dict]:
    base = base or config.root()
    rows = []
    for rec in load_index(base):
        if solved_only and not rec.get("solved"):
            continue
        sim = similarity(query, rec)
        if sim >= min_sim:
            rows.append({"sim": sim, **{k: rec.get(k) for k in (
                "machine", "solved", "ports", "services", "products", "os",
                "confirmed_categories", "actions", "root_s")}})
    rows.sort(key=lambda r: r["sim"], reverse=True)
    return rows[:top]


BIAS_MAX = 0.30  # score multiplier cap: 1 + BIAS_MAX at sim 1.0


def category_bias(query: dict, base: Path | None = None,
                  min_sim: float = 0.25) -> dict[str, dict]:
    """category -> {mult, source, sim}: evidence-based next-hyp boost from the
    most similar *solved* boxes. Deterministic; empty when no index.
    Pathological runs (the Autopilot anti-pattern: >=150 actions) never seed
    biases — they are the behaviour we are trying to avoid repeating."""
    bias: dict[str, dict] = {}
    for hit in rank(query, base, top=3, solved_only=True, min_sim=min_sim):
        if (hit.get("actions") or 0) >= 150:
            continue
        mult = 1.0 + BIAS_MAX * hit["sim"]
        for cat in hit.get("confirmed_categories") or []:
            prev = bias.get(cat)
            if prev is None or hit["sim"] > prev["sim"]:
                bias[cat] = {"mult": round(mult, 4), "source": hit["machine"],
                             "sim": hit["sim"]}
    return bias


def query_from_workspace(workspace: Path) -> dict:
    fp = parse_nmap(workspace)
    return {k: sorted(v) for k, v in fp.items()}


_CACHE: dict[str, list[dict]] = {}


def hint_block(workspace: Path, base: Path | None, mode: str) -> str:
    """Prompt-injection block for the first turn of an HTB run (fail-open)."""
    if mode != "htb":
        return ""
    key = str(workspace)
    if key not in _CACHE:
        try:
            q = query_from_workspace(workspace)
            hits = rank(q, base, top=2) if (q["ports"] or q["services"]) else []
            _CACHE[key] = hits
        except Exception:
            _CACHE[key] = []
    hits = [h for h in _CACHE[key] if (h.get("actions") or 0) < 150]
    if not hits:
        return ""
    lines = [f"  {h['machine']} (sim {h['sim']:.2f}"
             f"{', root ' + str(h['root_s']) + 's' if h.get('root_s') else ''}): "
             f"confirmed {', '.join(h.get('confirmed_categories') or []) or '?'}"
             for h in hits]
    cats = sorted({c for h in hits for c in (h.get("confirmed_categories") or [])})
    lines.append(f"  → bias new hypotheses toward categories that worked there: "
                 f"{', '.join(cats)}")
    return "--- SIMILAR SOLVED BOXES (fingerprint index) ---\n" + "\n".join(lines)


def to_json(rec: dict) -> str:
    return json.dumps(rec, indent=2)
