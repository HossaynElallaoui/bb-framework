#!/usr/bin/env python3
"""
Multi-agent driver: round-robins recon-agent / web-agent / ad-agent /
privesc-agent / linux-privesc-agent as separate `opencode run` invocations,
all coordinating
through one shared state.json (mailbox + hypothesis board) - see
lib/state.py and agents/*.md for the protocol each specialist follows.

This script itself calls no model and does no reasoning - it's a plain
deterministic scheduler, same philosophy as state.py's dumb blackboard:
cheap, inspectable, no hidden LLM judgment in the loop itself.

What it does each round:
  1. gives each specialist one turn (sequential by default; --parallel
     submits all turns simultaneously - state mutations are flock-
     serialized in lib/state.py, so mailbox/hypothesis writes can't clobber)
  2. after every round, reloads state.json and stops the whole run the
     moment a "flag" OR "root" milestone shows up (either means the box
     is owned; a stalled run may never get around to recording "flag")
  3. prints a benchmark summary after every round so you can watch
     progress (or lack of it) without digging into state.json yourself
  4. stops after --max-rounds if nothing resolves

Live progress visibility: run scripts/dashboard.py alongside - it reads
state.json directly (auto-refresh), so milestones, mailbox traffic,
hypothesis status and dead ends render while the agents work, using the
same file the specialists update after every action.

SESSION CONTINUITY (wired in): each specialist's first turn runs with
--format json just to capture its session id (opencode emits ndjson
events, each carrying a "sessionID" field - verified against opencode
1.18.x). Every later turn reuses it via -s/--session, so web-agent's
round 3 remembers what it tried in round 1 IN ADDITION to state.json
(already-tried / is-known-failed / inbox remain the coordination
channel of record). If capture fails on a turn (crash before any
event, zero JSON in stdout), that turn is lost to memory only - the
next capture-enabled turn re-registers a fresh session id without
breaking anything else.

Usage:
    python3 scripts/multi_agent_run.py \\
        --workspace labs/HTB/machines/cap \\
        --target 10.129.116.217 --machine cap --mode htb \\
        --model dahl/zai-org/GLM-5.3-Flash \\
        --max-rounds 20
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.state import TargetState  # noqa: E402

SPECIALISTS = ["recon-agent", "web-agent", "ad-agent", "privesc-agent", "linux-privesc-agent"]
MODE_FILES = {"htb": "modes/htb.md", "bugbounty": "modes/bugbounty.md"}

# parallel mode: serialize console prints and session-id registration
_PRINT_LOCK = threading.Lock()

SESSION_ID_RE = re.compile(r'"sessionID"\s*:\s*"(ses_[A-Za-z0-9]+)"')


def capture_session_id(stdout: str) -> str | None:
    """Pull the session id out of `opencode run --format json` output.

    Each emitted event is one JSON object carrying "sessionID" (even
    error events do). Try per-line JSON parsing first, fall back to a
    regex over the whole stdout for opencode versions that prefix or
    interleave noise around the ndjson stream."""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            sid = json.loads(line).get("sessionID")
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(sid, str) and sid.startswith("ses_"):
            return sid
    m = SESSION_ID_RE.search(stdout)
    return m.group(1) if m else None


def build_prompt(agent: str, workspace: str, target: str, machine: str, mode: str) -> str:
    agent_md = (ROOT / "agents" / f"{agent}.md").read_text()
    mode_md = (ROOT / MODE_FILES[mode]).read_text()
    preamble_path = ROOT / "agents" / "_preamble.md"
    preamble = (preamble_path.read_text().replace("<ROLE>", agent)
                if preamble_path.exists() else "")
    return f"""{preamble}

You are {agent}, running as your own process in a multi-agent team.

WORKSPACE={workspace}
TARGET={target}
MACHINE={machine}
MODE={mode.upper()}

Read your own role file and the mode policy below in full before doing
anything. Then take exactly one turn: drain your inbox, do the work your
role file describes, record everything through lib/state.py's CLI, and
hand off what you find. Stop at the end of this one turn - a later round
will give you another turn.

--- YOUR ROLE: agents/{agent}.md ---
{agent_md}

--- MODE POLICY: {MODE_FILES[mode]} ---
{mode_md}
"""


def build_command(agent: str, prompt: str, model: str | None,
                   session_ids: dict[str, str]) -> list[str]:
    cmd = ["opencode", "run"]
    if model:
        cmd += ["-m", model]
    if agent in session_ids:
        # continuation turn: reuse this specialist's own session across
        # rounds so its conversation carries over (state.json also carries
        # over - the two are complementary, not substitutes)
        cmd += ["-s", session_ids[agent]]
    else:
        # first turn for this agent: request the ndjson stream so we can
        # capture its session id for the turns above
        cmd += ["--format", "json"]
    cmd += ["--dir", str(ROOT), prompt]
    return cmd


def run_agent_turn(agent: str, workspace: str, target: str, machine: str,
                    mode: str, model: str | None, session_ids: dict[str, str],
                    log_dir: Path, runner=subprocess.run) -> None:
    prompt = build_prompt(agent, workspace, target, machine, mode)
    cmd = build_command(agent, prompt, model, session_ids)

    with _PRINT_LOCK:
        print(f"\n=== {agent} turn ===", flush=True)
    try:
        env = dict(os.environ)
        env["BB_WORKSPACE"] = workspace
        env["BB_TARGET"] = target
        env["BB_MODE"] = mode
        env["PATH"] = f"{ROOT}:{env.get('PATH', '')}"
        result = runner(cmd, capture_output=True, text=True, timeout=900, env=env)
    except subprocess.TimeoutExpired:
        log_file = log_dir / f"{agent}-{int(time.time())}.log"
        log_file.write_text(f"--- TIMED OUT after 900s (cmd: {' '.join(cmd)}) ---\n")
        with _PRINT_LOCK:
            print(f"[{agent}] turn timed out after 900s - see {log_file}", file=sys.stderr)
        return
    except Exception as e:  # one hung/crashed agent must not take down the round
        with _PRINT_LOCK:
            print(f"[{agent}] turn crashed: {e}", file=sys.stderr)
        return

    log_file = log_dir / f"{agent}-{time.time_ns()}.log"
    log_file.write_text(f"--- STDOUT ---\n{result.stdout}\n--- STDERR ---\n{result.stderr}\n")
    with _PRINT_LOCK:
        print(result.stdout[-2000:])  # tail only, keep console readable
    if result.returncode != 0:
        print(f"[{agent}] exited {result.returncode} - see {log_file}", file=sys.stderr)

    if agent not in session_ids:
        sid = capture_session_id(result.stdout)
        if sid:
            with _PRINT_LOCK:
                session_ids[agent] = sid
                print(f"[{agent}] session captured: {sid}")
        else:
            with _PRINT_LOCK:
                print(f"[{agent}] WARNING: no sessionID in output - next turn starts fresh",
                      file=sys.stderr)


def run_parallel_round(args, workspace: str, log_dir: Path,
                       session_ids: dict[str, str]) -> None:
    """One round = all specialists' turns submitted at once. Each is its own
    opencode process touching its own mailbox lane; state mutations are
    safe because every mutating lib/state.py CLI call flock-serializes on
    <workspace>/.state.lock and saves are atomic."""
    workers = max(1, min(args.max_workers, len(args.agents)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(run_agent_turn, agent, workspace, args.target,
                        args.machine, args.mode, args.model, session_ids, log_dir):
            agent
            for agent in args.agents
        }
        for _ in as_completed(futs):
            pass  # run_agent_turn logs its own errors; nothing to collect


def milestone_reached(workspace: Path, rnd: int, after_agent: str | None) -> bool:
    """Stop condition for the whole run: 'flag' OR 'root' on the board.
    'flag' is the canonical end marker, but 'root' alone already means the
    box is owned - waiting for a 'flag' nobody remembered to mark is how a
    finished run loops to --max-rounds."""
    state = TargetState.load(workspace)
    done = sorted({"flag", "root"} & set(state.milestones))
    if not done:
        return False
    who = f", after {after_agent}" if after_agent else ""
    print(f"\n{'/'.join(done)} milestone recorded at round {rnd}{who} - stopping.")
    print(json.dumps(state.benchmark_summary(), indent=2))
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--machine", required=True)
    p.add_argument("--mode", choices=["htb", "bugbounty"], default="htb")
    p.add_argument("--model", default=None, help="provider/model, e.g. dahl/zai-org/GLM-5.3-Flash")
    p.add_argument("--max-rounds", type=int, default=20)
    p.add_argument("--parallel", action="store_true",
                   help="all specialists take their turns concurrently each round "
                        "(state.json mutations are flock-serialized in lib/state.py); "
                        "watch for provider rate limits with the free models")
    p.add_argument("--max-workers", type=int, default=5,
                   help="max concurrent specialists per round in --parallel mode")
    p.add_argument("--agents", nargs="*", default=SPECIALISTS,
                    help="subset/order of specialists to run each round")
    args = p.parse_args()

    workspace = Path(args.workspace)
    log_dir = workspace / "agent_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    session_ids: dict[str, str] = {}  # populated from each agent's first turn (see SESSION CONTINUITY above)

    # bootstrap/refresh workspace metadata so the dashboard and benchmark
    # see the run even before the first specialist writes anything; an
    # existing non-empty target/mode wins (TargetState.load only falls
    # back to these when state.json is missing or blank)
    TargetState.load(workspace, target=args.target, mode=args.mode).save()

    for rnd in range(1, args.max_rounds + 1):
        print(f"\n########## ROUND {rnd}/{args.max_rounds} ##########")
        if args.parallel:
            run_parallel_round(args, str(workspace), log_dir, session_ids)
        else:
            for agent in args.agents:
                run_agent_turn(agent, str(workspace), args.target, args.machine,
                               args.mode, args.model, session_ids, log_dir)
                if milestone_reached(workspace, rnd, agent):
                    return

        if milestone_reached(workspace, rnd, None):
            return

        state = TargetState.load(workspace)
        print(f"\n--- round {rnd} summary ---")
        print(json.dumps(state.benchmark_summary(), indent=2))

    print(f"\nmax rounds ({args.max_rounds}) reached without a flag/root milestone.")
    state = TargetState.load(workspace)
    print(json.dumps(state.benchmark_summary(), indent=2))


if __name__ == "__main__":
    main()
