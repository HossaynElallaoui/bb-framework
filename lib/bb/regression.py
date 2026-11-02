"""§1.4 regression benchmark gate.

Pins a baseline from a saved benchmark run (the Connected gold run: 23
actions, 1 dead end, root in ~567s) and fails any engine/prompt change whose
re-run regresses action count, dead-end count, or time-to-root beyond a
tolerance band. Compare-only mode is cheap and CI-friendly; `--run` mode
re-runs the lab in a scratch workspace, snapshots it, compares, and cleans up.

Exit codes: 0 pass, 1 regression/timeout, 2 usage or config error.
"""

from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path

from lib.bb import benchmark, config, statex, ui

# Metrics the gate evaluates, with regression direction and default bands.
# "pct_up"      — more is worse (actions, wall-clock times)
# "count_down"  — fewer is worse (confirmed hypotheses)
# "dead_ends"   — more is worse, with a small absolute floor so 1->2 on a
#                 baseline of 1 is not an automatic fail
DEFAULT_TOLERANCES: dict[str, dict] = {
    "unique_actions": {"kind": "pct_up", "pct": 20},
    "dead_ends": {"kind": "dead_ends", "pct": 50, "abs": 1},
    "time_to_user_s": {"kind": "pct_up", "pct": 25},
    "time_to_root_s": {"kind": "pct_up", "pct": 25},
    "time_to_flag_s": {"kind": "pct_up", "pct": 25},
    "hypotheses_confirmed": {"kind": "count_down", "pct": 25, "abs": 1},
}


def baselines_dir(base: Path | None = None) -> Path:
    return (base or config.root()) / "benchmark" / "baselines"


def baseline_path(machine: str, base: Path | None = None) -> Path:
    return baselines_dir(base) / f"{machine.lower()}.json"


def load_baseline(machine: str, base: Path | None = None) -> dict | None:
    return config.read_json(baseline_path(machine, base), default=None)


def _metric(payload: dict, key: str):
    """Saved runs use flat keys; snapshot payloads may nest under 'auto'."""
    val = payload.get(key)
    if val is None and isinstance(payload.get("auto"), dict):
        val = payload["auto"].get(key)
    return val


def _runs_for_machine(machine: str, base: Path | None) -> list[Path]:
    prefix = machine.lower()
    out = []
    for p in benchmark.run_paths(base):
        stem = p.stem.lower()
        if stem == prefix or stem.startswith(prefix + "-"):
            out.append(p)
    return out


def pick_best_run(machine: str, base: Path | None = None) -> Path | None:
    """Deterministic pin default: the matching run with the fewest actions."""
    best, best_actions = None, None
    for p in _runs_for_machine(machine, base):
        r = benchmark.load_run(p)
        try:
            actions = int(_metric(r, "unique_actions") or 0)
        except (TypeError, ValueError):
            continue
        if best_actions is None or actions < best_actions:
            best, best_actions = p, actions
    return best


def pick_latest_run(machine: str, base: Path | None = None) -> Path | None:
    runs = _runs_for_machine(machine, base)
    return runs[-1] if runs else None


def pin_baseline(machine: str, run_file: Path, base: Path | None = None,
                 tolerances: dict | None = None, notes: str = "") -> dict:
    base = base or config.root()
    run = benchmark.load_run(run_file)
    metrics: dict[str, float] = {}
    for key in DEFAULT_TOLERANCES:
        val = _metric(run, key)
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            metrics[key] = val
    if not metrics:
        raise ValueError(f"run file has no gatable metrics: {run_file}")
    data = {
        "machine": machine,
        "pinned_from": Path(run_file).name,
        "pinned_at": int(time.time()),
        "metrics": metrics,
        "tolerances": tolerances or DEFAULT_TOLERANCES,
        "notes": notes,
    }
    out = baseline_path(machine, base)
    out.parent.mkdir(parents=True, exist_ok=True)
    config.write_json(out, data)
    return data


def _band(baseline_val: float, tol: dict) -> str:
    kind = tol.get("kind", "pct_up")
    if kind == "pct_up":
        return f"<= {baseline_val * (1 + tol.get('pct', 0) / 100):.4g}"
    if kind == "dead_ends":
        allow = max(tol.get("abs", 0), baseline_val * tol.get("pct", 0) / 100)
        return f"<= {baseline_val + allow:.4g}"
    if kind == "count_down":
        allow = max(tol.get("abs", 0), baseline_val * tol.get("pct", 0) / 100)
        return f">= {baseline_val - allow:.4g}"
    return "?"


def _fails(baseline_val: float, observed, tol: dict) -> bool:
    if observed is None:
        return True  # metric never reached — the worst regression
    kind = tol.get("kind", "pct_up")
    if kind == "pct_up":
        return observed > baseline_val * (1 + tol.get("pct", 0) / 100)
    if kind == "dead_ends":
        allow = max(tol.get("abs", 0), baseline_val * tol.get("pct", 0) / 100)
        return observed > baseline_val + allow
    if kind == "count_down":
        allow = max(tol.get("abs", 0), baseline_val * tol.get("pct", 0) / 100)
        return observed < baseline_val - allow
    return False


def compare(baseline: dict, observed_payload: dict) -> dict:
    """Pure verdict computation. Returns rows + regressions + verdict."""
    tols = baseline.get("tolerances") or DEFAULT_TOLERANCES
    rows, regressions = [], []
    for key, bval in (baseline.get("metrics") or {}).items():
        tol = tols.get(key)
        oval = _metric(observed_payload, key)
        if tol is None:
            rows.append([key, bval, oval if oval is not None else "-", "-", "-",
                         "INFO"])
            continue
        band = _band(bval, tol)
        if oval is None:
            verdict = "MISS"
        elif _fails(bval, oval, tol):
            verdict = "REGRESS"
        else:
            better = (oval > bval) if tol.get("kind") == "count_down" else (oval < bval)
            verdict = "IMPROVED" if better else "PASS"
        delta = "-" if oval is None else f"{oval - bval:+.4g}"
        rows.append([key, bval, oval if oval is not None else "-", delta, band,
                     verdict])
        if verdict in ("REGRESS", "MISS"):
            regressions.append(
                f"{key}: baseline {bval}, observed {oval if oval is not None else 'never reached'} "
                f"(band {band})")
    verdict = "pass" if not regressions else "regress"
    return {"verdict": verdict, "rows": rows, "regressions": regressions}


def run_gate(machine: str, base: Path, target: str | None = None,
             model: str | None = None, max_rounds: int = 20,
             max_minutes: float | None = None, dry_run: bool = False,
             keep: bool = False, no_ui: bool = False) -> tuple[dict, Path | None]:
    """Re-run the lab in a scratch workspace, snapshot it, compare vs baseline.

    Returns (compare_payload, snapshot_path). Raises ValueError on config
    problems (no baseline, no target). A wall-clock watchdog sets the runner's
    pause sentinel at the deadline; an over-long run is reported as a timeout
    regression rather than hanging the gate.
    """
    from lib.bb import runner  # local import: heavy module, compare-only paths skip it

    baseline = load_baseline(machine, base)
    if not baseline:
        raise ValueError(f"no baseline pinned for {machine!r} — "
                         f"`bb benchmark pin --machine {machine}` first")
    target = target or _htb_target(base, machine)
    if not target:
        raise ValueError(f"no target for {machine!r} — pass --target or pin "
                         f"programs/htb/{machine.lower()}.json")
    if max_minutes is None:
        root_s = (baseline.get("metrics") or {}).get("time_to_root_s") or 600
        max_minutes = max(15.0, root_s * 3 / 60)

    stamp = int(time.time())
    scratch = base / "labs" / "HTB" / "machines" / f"{machine}-gate-{stamp}"
    snapshot_path: Path | None = None
    deadline = {"hit": False}

    def _watchdog() -> None:
        if dry_run:
            return  # dry runs finish instantly; never arm the deadline
        time.sleep(max_minutes * 60)
        deadline["hit"] = True
        try:
            statex.request_pause(scratch)
            ui.log("bb", f"gate watchdog: {max_minutes:.0f}min deadline — "
                         f"pause sentinel set", "warn")
        except Exception:
            pass

    threading.Thread(target=_watchdog, daemon=True).start()
    try:
        rc = runner.run(runner.RunOptions(
            workspace=scratch, target=target, machine=machine, mode="htb",
            model=model, max_rounds=max_rounds,
            agents=list(config.ROLE_SPECIALISTS),
            no_ui=no_ui, dry_run=dry_run, base=base))
        if rc == 2:
            raise ValueError("gate run failed the scope gate or had no target")
        snapshot_path = benchmark.snapshot(scratch, base)
        payload = compare(baseline, benchmark.load_run(snapshot_path))
        if deadline["hit"]:
            payload["verdict"] = "regress"
            payload["regressions"].append(
                f"gate-timeout: run exceeded {max_minutes:.0f}min wall clock")
            payload["rows"].append(["gate-timeout", f"<={max_minutes:.0f}min",
                                    "exceeded", "-", "-", "REGRESS"])
        payload["machine"] = machine
        payload["baseline_file"] = config.rel(baseline_path(machine, base), base)
        payload["snapshot_file"] = config.rel(snapshot_path, base)
        payload["workspace"] = config.rel(scratch, base)
        return payload, snapshot_path
    finally:
        if not keep and scratch.exists():
            shutil.rmtree(scratch, ignore_errors=True)


def _htb_target(base: Path, machine: str) -> str | None:
    data = config.read_json(base / "programs" / "htb" / f"{machine.lower()}.json",
                            default={}) or {}
    return data.get("target")
