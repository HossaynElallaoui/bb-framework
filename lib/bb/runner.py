"""The deterministic round-robin driver behind `bb run`.

Same design principle as multi_agent_run.py: this module calls no model and
does no reasoning. It schedules one turn per specialist, round-robins, and
stops the instant a stop milestone exists. On top of the original driver it
adds: persisted session IDs, heartbeat/resume, SIGINT-safe flushing, an
operator pause sentinel, scope re-verification every round, crash backoff,
stall warnings, and a rich live panel.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from lib.bb import config, context, policy, ratelimit, scope, statex, ui, verify
from lib.bb.session import OpenCodeServer
from lib.state import TargetState

SESSION_ID_RE = re.compile(r'"sessionID"\s*:\s*"(ses_[A-Za-z0-9]+)"')
STOP_MILESTONES = ("root", "flag", "validated-finding")
_PRINT_LOCK = threading.Lock()

DEFAULT_PREAMBLE = """You are the <ROLE> specialist inside `bb`. Take exactly one turn, then stop.
1. Drain your inbox: `bb state $BB_WORKSPACE inbox --for <ROLE>`.
2. Dedup check: `bb state $BB_WORKSPACE already-tried --cmd "<cmd>"` before proposing a command.
3. Check the skill library: `bb skills "<keywords>"` before hand-rolling a technique. For standard multi-step chains prefer a composite bundle: `bb composite list`.
4. Submit the action to critic-agent (`bb gate --agent <ROLE> ...`). If BLOCKed, pick the next-cheapest open hypothesis.
5. Act (hexstrike MCP, shell via capture-command.py, or Burp).
6. Record: `bb state ... record-action/update-hyp/mark-failed/mark-milestone`.
7. Hand off: `bb state ... post-msg --for <next-role>` if needed.
8. Stop. Do not chain a second action in this invocation.
"""


@dataclass
class RunOptions:
    workspace: Path | None = None
    target: str | None = None
    machine: str | None = None
    program: str | None = None
    mode: str = "htb"
    model: str | None = None
    max_rounds: int = 20
    parallel: int | None = None
    max_workers: int = 5
    agents: list[str] = field(default_factory=lambda: list(config.ROLE_SPECIALISTS))
    timeout: int = 900
    no_ui: bool = False
    dry_run: bool = False
    resume: bool = False
    verify_confirms: bool = True
    base: Path | None = None


class _Interrupt:
    def __init__(self):
        self.flag = False

    def install(self):
        def handler(signum, frame):
            # Never raise here: a KeyboardInterrupt mid-flock could tear a
            # state write. We only set the flag; the loop exits after the
            # in-flight turn and flushes state.
            first = not self.flag
            self.flag = True
            if first:
                with _PRINT_LOCK:
                    print("\n[bb] SIGINT received — finishing the in-flight turn, "
                          "flushing state, then exiting resumable.", file=sys.stderr)
        try:
            signal.signal(signal.SIGINT, handler)
        except (ValueError, OSError):
            pass

    def __bool__(self):
        return self.flag


def capture_session_id(stdout: str) -> str | None:
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            sid = json.loads(line).get("sessionID")
        except (ValueError, TypeError):
            continue
        if isinstance(sid, str) and sid.startswith("ses_"):
            return sid
    m = SESSION_ID_RE.search(stdout)
    return m.group(1) if m else None


def _read_preamble(base: Path) -> str:
    p = base / "agents" / "_preamble.md"
    return p.read_text() if p.exists() else DEFAULT_PREAMBLE


def build_prompt(agent: str, workspace: Path, target: str, machine: str,
                 mode: str, base: Path, continuation: bool = False,
                 since: float = 0.0, round_no: int = 0,
                 state: TargetState | None = None) -> str:
    state = state or TargetState.load(workspace)
    if continuation:
        delta = context.state_delta(state, agent, since=since,
                                    workspace=workspace)
        return f"""CONTINUE round {round_no} as {agent}. Your session already
holds your role, mode policy, and prior turns.

{delta}

Take exactly one turn now, then stop. Do not repeat a command already in
WARM; run `bb state $BB_WORKSPACE already-tried --cmd "<cmd>"` if unsure.
"""

    role = (base / "agents" / f"{agent}.md").read_text()
    mode_rel = config.MODE_FILES.get(mode, config.MODE_FILES["htb"])
    mode_md = (base / mode_rel).read_text()
    preamble = _read_preamble(base).replace("<ROLE>", agent)
    state_summary = context.full_state_summary(state, agent, workspace=workspace)
    hot_warm = context.state_delta(state, agent, since=0.0,
                                   budget_tokens=context.STATE_TOKEN_BUDGET,
                                   workspace=workspace)
    skill = context.skill_hint(base, agent, target, machine, mode)
    skill_block = f"\n--- BEST-MATCH SKILL (cached) ---\n{skill}\n" if skill else ""
    sim_block = ""
    try:
        from lib.bb import fingerprint
        sim_block = fingerprint.hint_block(workspace, base, mode)
    except Exception:
        sim_block = ""
    if sim_block:
        sim_block = f"\n{sim_block}\n"
    return f"""{preamble}

WORKSPACE={workspace}
TARGET={target}
MACHINE={machine}
MODE={mode.upper()}
BB_CLI=bb

--- STATE SUMMARY (tiered; query for detail) ---
{state_summary}

--- HOT/WARM DELTA (COLD via state CLI) ---
{hot_warm}
{skill_block}{sim_block}
--- YOUR ROLE: agents/{agent}.md ---
{role}

--- MODE POLICY: {mode_rel} ---
{mode_md}

You have a persistent session for this run. Later turns receive only a
HOT/WARM delta, so use the state CLI for anything not shown here.
1. Work the highest confidence/cost open hypothesis
2. Do NOT repeat commands already run
3. Do NOT retry known dead ends
4. Drain your inbox: `bb state $BB_WORKSPACE inbox --for {agent}`
5. Run critic gate before acting: `bb gate --workspace $BB_WORKSPACE --agent {agent} --mode "$BB_MODE" --target "<target>" --cmd "<cmd>"`

Take exactly one turn now, then stop.
"""


def _build_command(agent: str, prompt: str, model: str | None,
                   sessions: dict[str, str], base: Path) -> list[str]:
    cmd = ["opencode", "run", "--auto"]
    if model:
        cmd += ["-m", model]
    if agent in sessions:
        cmd += ["-s", sessions[agent]]
    else:
        cmd += ["--format", "json"]
    cmd += ["--dir", str(base), prompt]
    return cmd


def _env(root: Path, workspace: Path, target: str, mode: str) -> dict:
    env = os.environ.copy()
    env["BB_CLI"] = str(root / "bb")
    env["BB_WORKSPACE"] = str(workspace)
    env["BB_TARGET"] = target or ""
    env["BB_MODE"] = mode
    try:
        from lib.bb import scope as scope_mod
        pol = scope_mod.load_policy(program=None, workspace=workspace, mode=mode, base=root)
        if pol and pol.rate_per_min:
            env["BB_RATE_PER_MIN"] = str(pol.rate_per_min)
        if pol and pol.required_header:
            env["BB_REQUIRED_HEADER"] = pol.required_header
    except Exception:
        pass
    env["PATH"] = f"{root}:{env.get('PATH', '')}"
    return env


@dataclass
class TurnResult:
    agent: str
    ok: bool
    session: str | None = None
    returncode: int = 0
    error: str = ""
    output_tail: str = ""
    log_file: str = ""
    empty: bool = False
    tokens: dict = field(default_factory=dict)
    cost: float = 0.0
    duration: float = 0.0
    server: bool = False


def _run_turn_http(agent: str, workspace: Path, target: str, machine: str,
                   mode: str, base: Path, model: str | None,
                   sessions: dict[str, str], seen: dict[str, float],
                   session_agents: dict[str, str],
                   log_file: Path, timeout: int, round_no: int,
                   server: OpenCodeServer) -> TurnResult:
    started = time.time()
    sid = sessions.get(agent)
    created = False
    if not sid:
        sid = server.create_session(workspace, title=f"bb {agent}")
        created = True
    session_agents[sid] = agent
    since = seen.get(agent, 0.0)
    prompt = build_prompt(agent, workspace, target, machine, mode, base,
                          continuation=not created, since=since,
                          round_no=round_no)
    seen[agent] = time.time()
    res = server.prompt(sid, prompt, directory=workspace, agent="build",
                        model=model, timeout=timeout)
    if not res.ok and ("404" in (res.error or "") or "not found" in (res.error or "").lower()):
        sid = server.create_session(workspace, title=f"bb {agent}")
        created = True
        session_agents[sid] = agent
        prompt = build_prompt(agent, workspace, target, machine, mode, base,
                              continuation=False, since=0.0, round_no=round_no)
        seen[agent] = time.time()
        res = server.prompt(sid, prompt, directory=workspace, agent="build",
                            model=model, timeout=timeout)
    log_file.write_text(
        f"--- HTTP SESSION {sid} ---\n"
        f"--- PROMPT ---\n{prompt}\n"
        f"--- TOKENS ---\n{json.dumps(res.tokens)}\n"
        f"--- TEXT ---\n{res.text}\n"
        f"--- ERROR ---\n{res.error}\n")
    empty = res.ok and not res.text.strip()
    reason = res.error
    if empty:
        reason = "empty turn"
    api_error = any(t in (reason or "").lower() for t in (
        "apierror", "rate limit", "429", "overloaded", "cannot connect"))
    if api_error:
        reason = "provider API error: " + (reason or "")[:200]
    if not res.ok and ("timed out" in (res.error or "").lower()
                       or "timeout" in (res.error or "").lower()):
        sessions.pop(agent, None)
        created = False
    return TurnResult(agent=agent, ok=res.ok, session=sid if created else None,
                      returncode=0 if res.ok else 1, error=reason,
                      output_tail=res.text[-1200:], log_file=str(log_file),
                      empty=empty, tokens=res.tokens, cost=res.cost,
                      duration=time.time() - started, server=True)


def run_turn(agent: str, workspace: Path, target: str, machine: str, mode: str,
             model: str | None, sessions: dict[str, str], log_dir: Path,
             timeout: int, dry_run: bool, base: Path,
             server: OpenCodeServer | None = None,
             seen: dict[str, float] | None = None,
             round_no: int = 0,
             session_agents: dict[str, str] | None = None) -> TurnResult:
    seen = seen if seen is not None else {}
    session_agents = session_agents if session_agents is not None else {}
    stamp = time.time_ns()
    log_file = log_dir / f"{agent}-{stamp}.log"
    if server is not None:
        return _run_turn_http(agent, workspace, target, machine, mode, base,
                              model, sessions, seen, session_agents, log_file,
                              timeout, round_no, server)
    prompt = build_prompt(agent, workspace, target, machine, mode, base)
    cmd = _build_command(agent, prompt, model, sessions, base)
    if dry_run:
        log_file.write_text(f"--- DRY RUN ---\ncmd: {' '.join(cmd[:6])} ...\n\n{prompt}\n")
        return TurnResult(agent=agent, ok=True, session=None, returncode=0,
                          output_tail="(dry-run)", log_file=str(log_file))
    started = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                env=_env(base, workspace, target, mode))
    except subprocess.TimeoutExpired:
        log_file.write_text(f"--- TIMED OUT after {timeout}s ---\ncmd: {' '.join(cmd)}\n")
        return TurnResult(agent=agent, ok=False, returncode=124,
                          error=f"timed out after {timeout}s", log_file=str(log_file))
    except Exception as e:
        log_file.write_text(f"--- CRASH ---\n{e}\n")
        return TurnResult(agent=agent, ok=False, returncode=1,
                          error=f"launch failed: {e}", log_file=str(log_file))

    out, err = result.stdout or "", result.stderr or ""
    log_file.write_text(f"--- STDOUT ---\n{out}\n--- STDERR ---\n{err}\n")
    sid = capture_session_id(out) if agent not in sessions else None
    api_error = any(t in (out + err) for t in (
        "APIError", "Cannot connect to API", "rate limit", "429", "overloaded"))
    empty = result.returncode == 0 and not (out.strip() or err.strip())
    ok = result.returncode == 0 and not api_error
    reason = ""
    if api_error:
        reason = "provider API error"
    elif result.returncode != 0:
        reason = f"exit {result.returncode}: {(err or out).strip()[-200:]}"
    elif empty:
        reason = "empty turn"
    return TurnResult(agent=agent, ok=ok, session=sid, returncode=result.returncode,
                      error=reason, output_tail=(out or err)[-1200:],
                      log_file=str(log_file), empty=empty,
                      duration=time.time() - started)


def _stop_hit(state: TargetState) -> str | None:
    hit = [m for m in STOP_MILESTONES if m in state.milestones]
    return hit[0] if hit else None


def _summary(workspace: Path) -> dict:
    state = TargetState.load(workspace)
    b = state.benchmark_summary()
    return {
        "milestones": ", ".join(sorted(state.milestones)) or "(none)",
        "actions": b["unique_actions"],
        "hypotheses": f"{b['hypotheses_confirmed']} confirmed / {b['hypotheses_refuted']} refuted / {b['hypotheses_total']} total",
        "dead_ends": b["dead_ends"],
        "time_to_first_path": f"{b['time_to_first_path_s']:.1f}s" if b["time_to_first_path_s"] else "-",
        "time_to_root": f"{b['time_to_root_s']:.1f}s" if b["time_to_root_s"] else "-",
        "time_to_flag": f"{b['time_to_flag_s']:.1f}s" if b["time_to_flag_s"] else "-",
    }


def _turn_event(workspace: Path, event: str, agent: str, round_no: int,
                **fields) -> None:
    """Append-only turn trace. Benchmarks derive active work from the end
    events, and the dashboard tails this file without touching state.json."""
    rec = {"ts": time.time(), "event": event, "agent": agent, "round": round_no}
    rec.update(fields)
    try:
        path = workspace / "agent_logs" / "turns.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with _PRINT_LOCK:
            with open(path, "a") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass


def _prewarm_skills(base: Path) -> None:
    script = base / "scripts" / "skills_lookup.py"
    if not script.exists():
        return
    try:
        subprocess.run([sys.executable, str(script), "--prewarm"],
                       capture_output=True, timeout=60)
    except Exception:
        pass


def run(opts: RunOptions) -> int:
    base = opts.base or config.root()
    mode = opts.mode
    workspace = Path(opts.workspace) if opts.workspace else None
    if opts.resume and workspace is None:
        print("bb run --resume requires --workspace (or --resume <workspace> via the CLI wrapper)",
              file=sys.stderr)
        return 2
    if workspace is None:
        workspace = config.workspace_for_run(mode, None, opts.machine, opts.target,
                                             opts.program, base)
    workspace = workspace if workspace.is_absolute() else base / workspace
    workspace.mkdir(parents=True, exist_ok=True)
    log_dir = workspace / "agent_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # bootstrap metadata without overwriting an existing target/mode
    TargetState.load(workspace, target=opts.target or "", mode=mode).save()
    state0 = TargetState.load(workspace)
    if opts.resume and state0.mode in ("htb", "bounty", "bugbounty"):
        mode = state0.mode
    if opts.resume and not opts.model:
        prev_model = state0.extra.get("bb_model")
        if isinstance(prev_model, str) and prev_model:
            opts.model = prev_model
    target = opts.target or state0.target
    program = opts.program or (workspace.name if "programs" in workspace.parts else None)
    machine = opts.machine or workspace.name
    if not target:
        print("bb run: no target — pass --target (or seed state.json with set-target)",
              file=sys.stderr)
        return 2

    # Apply benchmark-calibrated costs to hypotheses still using the flat 1.0
    # default, so every `bb state next-hyp` call in every specialist benefits.
    try:
        from lib.bb import priors as priors_mod
        applied: list[dict] = []
        pri = priors_mod.load_priors(base)
        statex.locked_update(workspace, lambda s: applied.extend(
            priors_mod.apply_to_state(s, pri)))
        if applied:
            ui.log("bb", f"calibrated {len(applied)} flat hypothesis cost(s) from priors")
    except Exception:
        pass

    # --- hard scope gate before any model call ---------------------------
    ok, verdict = scope.check_target(target, program=program, workspace=workspace,
                                     mode=mode, base=base)
    if not ok:
        ui.log("bb", f"scope DENY: {target} — {verdict.get('reason')}", "error")
        return 2
    ui.log("bb", f"scope ALLOW: {target} — {verdict.get('matched_rule') or verdict.get('reason')}")

    # --- resume reconstruction -----------------------------------------
    sessions = statex.get_sessions(workspace) if opts.resume else {}
    snapshot = statex.resume_snapshot(workspace)
    rounds_done = int((snapshot.get("heartbeat") or {}).get("rounds_completed", 0))
    start_round = rounds_done + 1 if opts.resume else 1
    if opts.resume:
        ui.panel("resume", "\n".join([
            f"workspace: {snapshot['workspace']}",
            f"target: {snapshot['target']}  mode: {snapshot['mode']}",
            f"open hypotheses: {snapshot['open_hypotheses']} (next: {snapshot['next_hypothesis']})",
            f"sessions: {', '.join(f'{k}={v[:12]}…' for k, v in sessions.items()) or '(none)'}",
            f"unread: {snapshot['unread']}",
            f"status: {snapshot['interrupted_reason']}",
        ]), style="cyan")

    policy_obj = scope.load_policy(program=program, workspace=workspace, mode=mode,
                                   target=target, base=base)
    parallel = opts.parallel
    if parallel is None:
        parallel = 5 if mode == "htb" else 1
    if policy_obj and policy_obj.max_concurrency:
        parallel = min(parallel, policy_obj.max_concurrency)
    if policy_obj and policy_obj.rate_per_min and policy_obj.rate_per_min < 60:
        parallel = 1  # honour a slow agreed ceiling; never fan out past it
    parallel = max(1, min(parallel, len(opts.agents), opts.max_workers))

    statex.set_many(workspace, {"bb_model": opts.model or "", "bb_mode": mode,
                                "bb_parallel": parallel})
    _prewarm_skills(base)
    limiter = ratelimit.AdaptiveLimiter(
        workspace, max_parallel=parallel,
        rate_per_min=(policy_obj.rate_per_min if policy_obj else None))

    guard = policy.AutopilotGuard(
        actions_threshold=int((priors_threshold(base))),
        dead_end_rate=0.25, min_actions=20)
    interrupt = _Interrupt()
    interrupt.install()

    server = None
    if not opts.dry_run and not os.environ.get("BB_NO_SERVER"):
        try:
            server = OpenCodeServer(
                base, log_dir=log_dir, model=opts.model,
                extra_env=_env(base, workspace, target, mode)).start()
            ui.log("bb", f"opencode server ready on {server.url} "
                         f"(sessions reused across turns)")
        except Exception as exc:
            ui.log("bb", f"server startup failed ({exc}) — falling back to "
                         f"per-turn `opencode run`", "warn")
            server = None

    live = ui.LiveStatus(no_ui=opts.no_ui or opts.dry_run)
    live.start()
    started = time.time()
    stop_reason = None
    turn_failures: dict[str, int] = {}
    seen: dict[str, float] = {}
    session_agents: dict[str, str] = {}
    streams: dict[str, str] = {}

    if server is not None:
        def _on_event(event: dict) -> None:
            etype = event.get("type")
            props = event.get("properties") or {}
            sid = props.get("sessionID") or ""
            agent = session_agents.get(sid, "bb")
            if etype == "message.part.delta" and props.get("field") == "text":
                chunk = props.get("delta") or ""
                if chunk:
                    streams[agent] = (streams.get(agent, "") + chunk)[-2000:]
                    live.update(stream_agent=agent,
                                stream_text=streams[agent][-600:])
            elif etype == "message.part.updated":
                part = props.get("part") or {}
                if part.get("type") == "tool":
                    state = part.get("state") or {}
                    if state.get("status") == "completed":
                        title = state.get("title") or part.get("tool") or "tool"
                        ui.log(agent, f"tool: {str(title)[:160]}")

        server.start_event_stream(_on_event)

    def refresh_state(round_no: int, active_agent: str | None = None, phase: str = "running"):
        st = TargetState.load(workspace)
        warns = guard.evaluate(st)
        if warns:
            try:
                statex.set_warnings(workspace, warns)
            except Exception:
                pass
        nxt = st.next_hypothesis()
        live.update(
            round=round_no, max_rounds=opts.max_rounds, state=phase,
            agent=active_agent or "-", workspace=config.rel(workspace, base),
            elapsed=time.time() - started, actions=len(st.actions),
            dead_ends=len(st.failed_paths), hypothesis=nxt.id if nxt else "-",
            milestones=sorted(st.milestones),
            warning=warns[0] if warns else "",
            progress=min(1.0, round_no / max(opts.max_rounds, 1)),
            limiter=limiter.snapshot(),
            tokens=statex.token_summary(workspace),
            sessions=len(sessions),
        )
        return st

    try:
        for rnd in range(start_round, opts.max_rounds + 1):
            if interrupt:
                stop_reason = "interrupted"
                break
            if statex.pause_requested(workspace):
                statex.clear_pause(workspace)
                stop_reason = "paused"
                ui.log("bb", "pause sentinel set — stopping after a clean flush")
                break

            # re-verify scope every round: scope.md may have changed while paused
            ok, verdict = scope.check_target(target, program=program, workspace=workspace,
                                             mode=mode, base=base)
            if not ok:
                ui.log("bb", f"scope changed to DENY: {verdict.get('reason')}", "error")
                stop_reason = "scope-denied"
                break

            state = refresh_state(rnd, phase="round")
            hit = _stop_hit(state)
            if hit:
                stop_reason = hit
                break
            statex.heartbeat(workspace, round=rnd, rounds_completed=rnd - 1,
                             phase="running", agent=None, model=opts.model or "")
            ui.log("bb", f"round {rnd}/{opts.max_rounds} — "
                         f"{len(state.actions)} actions, {len(state.failed_paths)} dead ends")

            def do(agent: str) -> TurnResult:
                turn_started = time.time()
                _turn_event(workspace, "turn_start", agent, rnd,
                            model=opts.model or "")
                try:
                    confirmed_before = {
                        h.id for h in TargetState.load(workspace).hypotheses.values()
                        if h.status == "confirmed"}
                except Exception:
                    confirmed_before = set()
                waited = limiter.wait_slot()
                if waited >= 2:
                    ui.log(agent, f"limiter held the turn {waited:.0f}s "
                                  f"({limiter.snapshot()['parallel']} slots)",
                           "warn")
                statex.heartbeat(workspace, round=rnd, agent=agent, phase="turn",
                                 rounds_completed=rnd - 1, model=opts.model or "")
                try:
                    res = run_turn(agent, workspace, target, machine, mode,
                                   opts.model, sessions, log_dir, opts.timeout,
                                   opts.dry_run, base, server=server, seen=seen,
                                   round_no=rnd, session_agents=session_agents)
                except Exception as exc:
                    res = TurnResult(agent=agent, ok=False, returncode=1,
                                     error=f"driver exception: {exc}")
                _turn_event(workspace, "turn_end", agent, rnd,
                            ok=bool(res.ok), error=(res.error or "")[:300],
                            duration=round(time.time() - turn_started, 3),
                            tokens=(res.tokens or {}).get("total"),
                            cost=res.cost or 0.0, server=bool(res.server))
                limited = ratelimit.is_rate_limit_error(
                    (res.error or "") + " " + (res.output_tail or ""))
                limiter.release(ok=res.ok, rate_limited=limited)
                if limited:
                    ui.log(agent, "provider rate limit — limiter halved "
                                  "concurrency and shared a cooldown", "warn")
                with _PRINT_LOCK:
                    if res.tokens or res.duration:
                        try:
                            statex.record_tokens(workspace, agent, res.tokens,
                                                 cost=res.cost, duration=res.duration)
                        except Exception:
                            pass
                    if res.session:
                        sessions[agent] = res.session
                        statex.set_session(workspace, agent, res.session)
                        ui.log(agent, f"session ready: {res.session[:18]}…")
                    if not res.ok:
                        turn_failures[agent] = turn_failures.get(agent, 0) + 1
                        statex.record_failure(workspace, agent, res.error or "unknown")
                        ui.log(agent, f"turn failed: {res.error} — backing off, "
                                      f"no same-action retry", "error")
                    elif res.empty:
                        statex.record_failure(workspace, agent, "empty turn")
                        ui.log(agent, "empty turn — recording and moving on", "warn")
                    else:
                        ui.log(agent, (res.output_tail or "(turn complete)").splitlines()[-1][:200])
                if opts.verify_confirms and server is not None and res.ok \
                        and not res.empty and not opts.dry_run:
                    _verify_new_confirms(agent, confirmed_before)
                return res

            def _verify_new_confirms(agent: str, confirmed_before: set) -> None:
                """§1.2: every confirm produced by this turn gets a cheap,
                differently-prompted second opinion on the existing evidence.
                A KICKBACK deterministically reverts the confirm."""
                try:
                    st = TargetState.load(workspace)
                except Exception:
                    return
                fresh = [h for h in st.hypotheses.values()
                         if h.status == "confirmed" and h.id not in confirmed_before]
                if not fresh:
                    return
                actions = [(a.command, a.result_summary)
                           for a in sorted(st.actions.values(),
                                           key=lambda a: a.timestamp)]
                for hyp in fresh:
                    _turn_event(workspace, "turn_start", "verifier", rnd,
                                model=opts.model or "", verify=hyp.id)
                    v = verify.second_opinion(server, workspace, hyp, agent,
                                              opts.model, actions)
                    tok = v.get("tokens") or {}
                    if tok or v.get("cost"):
                        try:
                            statex.record_tokens(workspace, "verifier", tok,
                                                 cost=v.get("cost") or 0.0,
                                                 duration=0.0)
                        except Exception:
                            pass
                    if v["verdict"] == "kickback":
                        verify.apply_kickback(workspace, hyp.id, v["reason"], agent)
                        ui.log("verifier", f"KICKBACK {hyp.id}: {v['reason']}",
                               "warn")
                    elif v["verdict"] == "agree":
                        verify.record_agree(workspace, hyp.id, agent)
                        ui.log("verifier", f"agree: {hyp.id} stands")
                    else:
                        verify.record_agree(workspace, hyp.id, agent,
                                            verdict=v["verdict"])
                        ui.log("verifier", f"verifier {v['verdict']} on {hyp.id}: "
                                           f"{v['reason']} — confirm stands",
                                           "warn")
                    _turn_event(workspace, "turn_end", "verifier", rnd,
                                ok=v["verdict"] in ("agree", "kickback"),
                                error=(v["reason"] or "")[:300]
                                if v["verdict"] == "error" else "",
                                verify=hyp.id, verdict=v["verdict"])

            ran = 0
            if parallel <= 1:
                for agent in opts.agents:
                    res = do(agent)
                    ran += 1
                    if not res.ok and not opts.dry_run and not ratelimit.is_rate_limit_error(res.error):
                        time.sleep(min(30, 2 ** min(turn_failures.get(agent, 1), 5)))
                    hit = _stop_hit(TargetState.load(workspace))
                    if hit:
                        stop_reason = hit
                        break
                    if interrupt:
                        if not res.ok:
                            ran = max(0, ran - 1)  # interrupted mid-turn: not complete
                        break
                    if statex.pause_requested(workspace):
                        break
            else:
                from concurrent.futures import (
                    FIRST_COMPLETED, ThreadPoolExecutor, wait as fut_wait)
                results: list[TurnResult] = []
                pool = ThreadPoolExecutor(max_workers=parallel)
                agent_iter = iter(opts.agents)
                futs: dict = {}
                for _ in range(min(parallel, len(opts.agents))):
                    a = next(agent_iter, None)
                    if a is not None:
                        futs[pool.submit(do, a)] = a
                try:
                    while futs and stop_reason is None:
                        done, _ = fut_wait(list(futs), return_when=FIRST_COMPLETED)
                        for fut in done:
                            futs.pop(fut, None)
                            try:
                                res = fut.result()
                            except Exception as exc:
                                res = TurnResult(agent="?", ok=False,
                                                 error=f"future failed: {exc}")
                            results.append(res)
                            ran += 1
                            # Check the instant this turn lands, not at the
                            # round barrier: a root/flag turn must stop the
                            # remaining specialists immediately.
                            hit = _stop_hit(TargetState.load(workspace))
                            if hit:
                                stop_reason = hit
                                break
                            if interrupt:
                                stop_reason = "interrupted"
                                break
                            if statex.pause_requested(workspace):
                                break
                            nxt = next(agent_iter, None)
                            if nxt is not None:
                                futs[pool.submit(do, nxt)] = nxt
                        if stop_reason is not None:
                            break
                finally:
                    for fut in futs:
                        fut.cancel()
                    pool.shutdown(wait=True, cancel_futures=True)
                if interrupt and stop_reason is None:
                    stop_reason = "interrupted"
                if stop_reason == "interrupted" and any(not r.ok for r in results):
                    ran = 0  # incomplete round: resume at this round

            # Only count the round as complete when every specialist got a
            # turn. An operator interrupt/pause mid-round resumes at this
            # round; action dedup prevents duplicate work.
            rounds_completed = rnd if ran >= len(opts.agents) else max(0, rnd - 1)
            statex.heartbeat(workspace, round=rnd, rounds_completed=rounds_completed,
                             phase="round-done", agent=None, model=opts.model or "")
            # one-line status for the dashboard/timeline (agents' inboxes do
            # not include it; it is addressed to the dashboard only)
            try:
                st_now = TargetState.load(workspace)
                statex.locked_update(workspace, lambda s: s.post_message(
                    "bb", "dashboard",
                    f"round {rnd} done: {len(st_now.actions)} actions, "
                    f"{len(st_now.failed_paths)} dead ends, "
                    f"{sum(1 for h in st_now.hypotheses.values() if h.status == 'open')} open hyps",
                    "info"))
            except Exception:
                pass
            refresh_state(rnd, phase="round-done")
            hit = _stop_hit(TargetState.load(workspace))
            if hit:
                stop_reason = hit
                break
            if interrupt:
                stop_reason = "interrupted"
                break
            if statex.pause_requested(workspace):
                statex.clear_pause(workspace)
                stop_reason = "paused"
                break
            time.sleep(0.2)

        if stop_reason is None:
            stop_reason = "max-rounds"
    finally:
        if server is not None:
            server.stop()
        live.stop()
        # flush a final heartbeat/mailbox-safe write; never exit mid-flock
        try:
            statex.heartbeat(workspace, phase="stopped", stop_reason=str(stop_reason),
                             rounds_completed=int((statex.last_active(workspace)
                                                   or {}).get("rounds_completed", 0)))
        except Exception:
            pass

    # Learning loop runs unconditionally (win or lose). It only writes
    # candidates for operator review; nothing is committed automatically.
    try:
        from lib.bb import learn
        learn.generate(workspace, base)
    except Exception:
        pass

    summary = _summary(workspace)
    note = {
        "interrupted": "Interrupted by operator; workspace is resumable with "
                       "`bb run --resume <workspace>`.",
        "paused": "Paused after a clean turn; resumable with `bb run --resume <workspace>`.",
        "scope-denied": "Stopped: scope gate denied. Edit programs/<slug>/scope.md deliberately "
                        "before resuming.",
        "max-rounds": f"Reached --max-rounds ({opts.max_rounds}) without a stop milestone.",
    }.get(stop_reason, f"Stopped on milestone: {stop_reason}.")
    ui.boxed_summary(f"bb run stopped — {stop_reason}", summary, note)
    if stop_reason == "interrupted":
        return 130
    if stop_reason == "scope-denied":
        return 2
    return 0


def priors_threshold(base: Path) -> int:
    try:
        from lib.bb import priors as priors_mod
        return int((priors_mod.load_priors(base).get("stall") or {}).get("actions_threshold", 60))
    except Exception:
        return 60
