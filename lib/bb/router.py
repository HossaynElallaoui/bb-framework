"""§1.1 multi-model router + §1.6 local fallback.

Not every turn needs the same reasoning weight. `models.yaml` maps task
types to an ordered model list (first healthy wins); the router classifies
each upcoming turn deterministically (agent role + run signals), picks the
model, and tracks per-(model, task-type) health so the routing table becomes
evidence-based instead of guessed.

§1.6 rides the same machinery: when the active model keeps producing
provider API errors (consecutive across agents — a bad day for a free
endpoint, not one flaky turn), the router escalates: next entry in the
task list, then the `fallback:` tier (local ollama), so a total free-API
outage degrades to a local model instead of stalling the run.

Without models.yaml everything is a passthrough: behavior is identical to
the single-model runner, and the stats still accumulate.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

try:
    import yaml
except ImportError:  # pyyaml is a stated dependency; degrade gracefully anyway
    yaml = None

from lib.bb import config

TASK_TYPES = ("recon-parse", "hypothesis-synthesis", "exploit-attempt",
              "report-draft")

# agent role -> default task type (deterministic classification; the run
# loop has no cheaper signal that is honest)
_ROLE_TASK = {
    "recon-agent": "recon-parse",
    "web-agent": "exploit-attempt",
    "ad-agent": "exploit-attempt",
    "privesc-agent": "exploit-attempt",
    "linux-privesc-agent": "exploit-attempt",
    "orchestrator": "hypothesis-synthesis",
    "verifier": "hypothesis-synthesis",
    "critic-agent": "hypothesis-synthesis",
}

ESCALATE_AFTER = 3  # consecutive API-error turns before switching models

_STATS_PATH = None  # set per-run via bind(); keeps the module import-light
_stats: dict = {}
_consecutive_api_errors = 0
_active_model: str | None = None


def models_yaml_path(base: Path | None = None) -> Path:
    return (base or config.root()) / "models.yaml"


def load_config(base: Path | None = None) -> dict:
    p = models_yaml_path(base)
    data = config.read_json(p, default=None)  # not json; read raw below
    if data is None:
        try:
            raw = p.read_text()
        except OSError:
            return {}
        if yaml is not None:
            try:
                data = yaml.safe_load(raw)
            except yaml.YAMLError:
                return {}
        else:
            return {}
    return data if isinstance(data, dict) else {}


def classify(agent: str) -> str:
    return _ROLE_TASK.get(agent, "exploit-attempt")


def bind(stats_path: Path | None) -> None:
    """Point the health store at this run's stats file and reset counters."""
    global _STATS_PATH, _stats, _consecutive_api_errors, _active_model
    _STATS_PATH = stats_path
    _stats = {}
    _consecutive_api_errors = 0
    _active_model = None
    if stats_path and stats_path.exists():
        try:
            data = json.loads(stats_path.read_text())
            if isinstance(data, dict):
                _stats = data.get("models") if isinstance(
                    data.get("models"), dict) else {}
        except (OSError, ValueError):
            pass


def _healthy(model: str) -> bool:
    st = _stats.get(model) or {}
    return not (st.get("consecutive_api_errors", 0) >= ESCALATE_AFTER)


def pick(base_model: str | None, agent: str, base: Path | None = None) -> str | None:
    """Model for this turn: task-type list (first healthy entry wins), with
    the run model prepended so an unconfigured task falls through to it."""
    cfg = load_config(base)
    task = classify(agent)
    chain = [base_model] if base_model else []
    chain += [m for m in ((cfg.get("tasks") or {}).get(task) or [])
              if isinstance(m, str) and m not in chain]
    for m in chain:
        if _healthy(m):
            return m
    for m in (cfg.get("fallback") or []):
        if isinstance(m, str) and _healthy(m):
            return m
    return base_model


def note(model: str | None, ok: bool, api_error: bool, task: str | None = None,
         empty: bool = False) -> None:
    """Record a turn outcome; escalates the active model on API-error storms."""
    global _consecutive_api_errors, _active_model
    if not model:
        return
    task = task or "unknown"
    st = _stats.setdefault(model, {}).setdefault(task, {
        "turns": 0, "ok": 0, "api_error": 0, "empty": 0,
        "consecutive_api_errors": 0})
    st["turns"] += 1
    st["ok" if ok else ("api_error" if api_error else "other")] = \
        st.get("ok" if ok else ("api_error" if api_error else "other"), 0) + 1
    if empty:
        st["empty"] = st.get("empty", 0) + 1
    st["consecutive_api_errors"] = 0 if ok else (
        st.get("consecutive_api_errors", 0) + (1 if api_error else 0))
    if api_error and not ok:
        _consecutive_api_errors += 1
    if ok:
        _consecutive_api_errors = 0
    _active_model = model
    flush()


def escalate(base_model: str | None, agent: str,
             base: Path | None = None) -> str | None:
    """Called when the API-error storm threshold is hit: mark the current
    model unhealthy and return the next candidate (task list, then fallback
    tier). Returns None when there is nowhere to go."""
    global _consecutive_api_errors
    if _consecutive_api_errors < ESCALATE_AFTER:
        return None
    cfg = load_config(base)
    task = classify(agent)
    chain = [base_model] if base_model else []
    chain += [m for m in ((cfg.get("tasks") or {}).get(task) or [])
              if m != base_model]
    chain += [m for m in (cfg.get("fallback") or [])
              if isinstance(m, str) and m not in chain]
    for m in chain:
        st = _stats.get(m) or {}
        if all((st.get(t, {}).get("consecutive_api_errors", 0) < ESCALATE_AFTER)
               for t in TASK_TYPES) or m not in _stats:
            _consecutive_api_errors = 0
            return m
    _consecutive_api_errors = 0
    return None


def flush() -> None:
    if _STATS_PATH is None:
        return
    try:
        _STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"updated_at": time.time(), "models": _stats},
                                  indent=2, default=str) + "\n")
        tmp.replace(_STATS_PATH)
    except OSError:
        pass


def summary() -> dict:
    return {"models": _stats, "consecutive_api_errors": _consecutive_api_errors,
            "active_model": _active_model}
