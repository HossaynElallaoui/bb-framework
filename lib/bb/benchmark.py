"""Benchmark scanning/comparison and calibrated-priors derivation."""

from __future__ import annotations

import time
from pathlib import Path

from lib.bb import config, priors
from lib.state import TargetState

FIELDS = [
    ("auto", "unique_actions", "actions"),
    ("auto", "dead_ends", "dead ends"),
    ("auto", "time_to_user_s", "to user (s)"),
    ("auto", "time_to_root_s", "to root (s)"),
    ("auto", "time_to_flag_s", "to flag (s)"),
    ("judged", "recon_quality", "recon /10"),
    ("judged", "hypothesis_quality", "hypothesis /10"),
    ("judged", "tool_selection", "tool /10"),
    ("judged", "web_reasoning", "web /10"),
    ("judged", "ad_reasoning", "ad /10"),
    ("judged", "privilege_escalation", "privesc /10"),
    ("judged", "false_assumptions", "false assum."),
    ("judged", "hints_required", "hints"),
]


def load_run(path: Path) -> dict:
    data = config.read_json(path, default={})
    if not isinstance(data, dict):
        return {}
    data["_file"] = Path(path).name
    return data


def run_paths(base: Path | None) -> list[Path]:
    return sorted(((base or config.root()) / "benchmark" / "runs").glob("*.json"))


def summary(base: Path | None = None) -> list[dict]:
    base = base or config.root()
    rows = []
    for p in run_paths(base):
        r = load_run(p)
        if not r:
            continue
        rows.append({
            "file": r.get("_file"),
            "model": r.get("model", "?"),
            "machine": r.get("machine", "?"),
            "actions": (r.get("auto") or {}).get("unique_actions", r.get("unique_actions")),
            "dead_ends": (r.get("auto") or {}).get("dead_ends", r.get("dead_ends")),
            "root_s": (r.get("auto") or {}).get("time_to_root_s", r.get("time_to_root_s")),
            "flag_s": (r.get("auto") or {}).get("time_to_flag_s", r.get("time_to_flag_s")),
        })
    return rows


def compare(paths: list[Path], base: Path | None = None) -> dict:
    runs = [load_run(Path(p)) for p in paths]
    labels = []
    for r in runs:
        labels.append(f"{r.get('model', '?')} / {r.get('machine', r.get('_file', '?'))}")
    rows = []
    for section, key, label in FIELDS:
        row = [label]
        for r in runs:
            val = (r.get(section) or {}).get(key)
            if val is None and section == "auto":
                val = r.get(key)  # saved runs use both shapes
            row.append(val if val is not None else "-")
        rows.append(row)
    return {"labels": labels, "rows": rows}


def derive(base: Path | None = None, write: bool = True) -> dict:
    data = priors.derive(base)
    if write:
        priors.save_priors(data, base=base)
    return data


def snapshot(workspace: Path, base: Path | None = None) -> Path:
    base = base or config.root()
    state = TargetState.load(workspace)
    payload = state.benchmark_summary()
    payload["model"] = state.extra.get("bb_model", "")
    payload["machine"] = Path(workspace).name
    tok = state.extra.get("bb_tokens") or {}
    agents = tok.get("agents") or {}
    payload["turns"] = int(tok.get("turns") or 0)
    payload["active_work_s"] = round(sum(
        float((a or {}).get("duration") or 0.0) for a in agents.values()), 1)
    payload["tokens_total"] = (tok.get("total") or {}).get("total", 0)
    payload["tokens_by_agent"] = {
        k: ((v or {}).get("tokens") or {}).get("total", 0)
        for k, v in agents.items()}
    out = base / "benchmark" / "runs" / f"{Path(workspace).name}-{int(time.time())}.json"
    config.write_json(out, payload)
    return out
