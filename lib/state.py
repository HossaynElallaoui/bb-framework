#!/usr/bin/env python3
"""
Persistent state + hypothesis engine for agentic-bug-hunter.

One state.json per target workspace (an HTB machine dir or a bounty program
dir), holding:
  - executed actions, deduped by normalized command text
  - ranked hypotheses (evidence, confidence, cost, test, result)
  - failed paths, explicitly blocked from silent retry
  - timestamped milestones, for benchmarking (time-to-user, time-to-root, ...)

This is the "biggest jump toward a Shannon-like workflow" piece: it gives
the orchestrator/critic a cheap, deterministic answer to "haven't we already
tried this?" and "what should we try next?" instead of re-deriving both from
the full conversation context every turn.

Wire it into your OpenCode loop as a pre/post hook around each tool call:

    from lib.state import TargetState

    state = TargetState.load(workspace_dir, target="10.129.x.x", mode="htb")

    # before running a tool:
    prior = state.already_tried(command)
    if prior:
        # hand this to the critic agent rather than silently skipping -
        # sometimes a repeat is justified (new creds, new port open)
        ...

    # after running it:
    state.record_action(command, result_summary)
    state.save()

Hypothesis engine usage:

    state.add_hypothesis("h1", "Apache Tomcat mgr allows PUT upload",
                          evidence="tomcat 8.5.19, /manager/html exposed",
                          confidence=0.7, cost=1.0,
                          test="PUT war via /manager/text/deploy")
    next_h = state.next_hypothesis()   # highest confidence/cost, status=open
    ...
    state.update_hypothesis("h1", status="confirmed", result="shell as tomcat")

Nothing here calls a model. It's pure bookkeeping + a deterministic ranking
function, so it's near-free to call every turn.

MAILBOX (multi-agent coordination)

Specialist agents (recon/web/AD/privesc - see agents/*.md) coordinate through
a shared mailbox in the same state.json rather than talking to each other
directly. Each specialist, run as its own `opencode run` invocation, has
shell access, so the mailbox is exposed as plain CLI subcommands rather than
a Python API - a free model shelling out to a documented command is far more
reliable than it writing correct inline Python every turn.

    # recon-agent posts a finding, addressed to web-agent specifically
    python3 lib/state.py <workspace> post-msg \\
        --from recon-agent --to web-agent --type finding \\
        --text "Tomcat 8.5.19 on :8080, /manager/html exposed, no auth"

    # or broadcast to everyone with --to all

    # web-agent checks its inbox at the start of its turn
    python3 lib/state.py <workspace> inbox --for web-agent

    # and marks messages read once it's acted on them, so the next
    # round doesn't re-process the same finding
    python3 lib/state.py <workspace> inbox --for web-agent --mark-read m3 m4

This is deliberately a dumb, durable blackboard, not a live channel - no
agent blocks waiting on a reply. The driver (scripts/multi_agent_run.py)
round-robins specialists; each one drains its inbox, does its work, and
posts what it found before the next specialist's turn.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# CLI subcommands that mutate state.json. When run under multi_agent_run
# --parallel, several specialists mutate the same workspace file in
# overlapping windows, so every mutating invocation takes an exclusive
# flock on <workspace>/.state.lock for its whole load->mutate->save
# critical section. Readers (dashboard, benchmark) need no lock - saves
# are atomic (write .tmp + os.replace), so a reader sees either the old
# or the new file, never a torn one.
MUTATING_CMDS = {"post-msg", "add-hyp", "update-hyp", "record-action",
                 "mark-failed", "mark-milestone", "set-target", "set-extra"}

# Keys TargetState owns. Anything else found on load (hand-added run
# metadata like Bedside's status/flags/completed_at) is stashed in
# .extra and written back verbatim on save() - agents and humans both
# grow state.json ad hoc, and a strict schema would silently delete
# their keys on the next mutation.
KNOWN_KEYS = {"target", "mode", "started_at", "milestones", "hypotheses",
              "actions", "failed_paths", "messages", "_next_msg_id"}

# Append-only action log. state.json keeps a compacted tail so dashboards
# and the pre-log schema keep working; TargetState.load() merges the full
# log back in. This keeps the hot path (record-action during a parallel
# run) at one small O_APPEND instead of rewriting every action ever seen.
ACTION_LOG_DIR = "state"
ACTION_LOG_NAME = "actions.jsonl"
ACTION_LOG_LOCK = ".actions.lock"
ACTION_SNAPSHOT_LIMIT = 200
ACTION_LOG_COMPACT_BYTES = 2 * 1024 * 1024
REJECTED_WRITES = "rejected-writes.jsonl"


def _reject(workspace, subcmd: str, payload: dict, reason: str) -> None:
    """Strict-mode write rejection: log the attempted mutation, never apply it."""
    import fcntl as _fcntl
    path = Path(workspace) / REJECTED_WRITES
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": _now(), "subcmd": subcmd, "payload": payload, "reason": reason}
        line = json.dumps(rec, default=str) + "\n"
        with open(path, "a") as fh:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
            fh.write(line)
            fh.flush()
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
    except OSError:
        pass
    print(f"rejected {subcmd}: {reason}", file=sys.stderr)
    raise SystemExit(2)


def _now() -> float:
    return time.time()


def _coerce_dict(raw: dict, cls) -> dict:
    """Schema-drift tolerance for keyed collections (actions/hypotheses):
    free-model agents occasionally append hand-shaped dicts instead of the
    CLI's record shape. Never crash on load - wrap the unknown shape in a
    valid record that preserves the raw payload as text."""
    out = {}
    for k, v in raw.items():
        if not isinstance(v, dict):
            out[k] = cls(key=k, command=f"non-dict record: {v!r}"[:200],
                         result_summary="schema drift") if cls is ActionRecord \
            else cls(id=k, statement=f"non-dict record: {v!r}"[:200])
            continue
        try:
            out[k] = cls(**v)
            continue
        except TypeError:
            blob = json.dumps(v, default=str)[:400]
            if cls is ActionRecord:
                out[k] = ActionRecord(
                    key=k, command=blob,
                    result_summary="free-form record - raw payload preserved")
            elif cls is Hypothesis:
                out[k] = Hypothesis(
                    id=k, statement=blob, evidence="(free-form record)",
                    result="schema drift - see statement for raw payload")
            else:  # hypotheses/actions are the keyed collections; widen here only
                raise
    return out


def _coerce_list(raw: list, cls) -> list:
    """List counterpart of _coerce_dict (failed_paths / messages)."""
    out = []
    for v in raw:
        if not isinstance(v, dict):
            out.append(cls(description=f"non-dict record: {v!r}"[:200],
                           reason="schema drift") if cls is FailedPath
                       else cls(id="m?", from_agent="drift", to_agent="drift",
                                msg_type="info", text=f"non-dict record: {v!r}"[:200]))
            continue
        try:
            out.append(cls(**v))
            continue
        except TypeError:
            blob = json.dumps(v, default=str)[:400]
            if cls is FailedPath:
                out.append(cls(description=blob,
                               reason="schema drift - raw record preserved"))
            elif cls is Message:
                out.append(cls(id="m?", from_agent="drift", to_agent="all",
                               msg_type="info", text=blob))
    return out


FLAG_ALIASES = {
    "-o": "--output", "-s": "--silent", "-k": "--insecure",
    "-L": "--location", "-i": "--include", "-v": "--verbose",
    "-A": "--user-agent", "-H": "--header", "-X": "--request",
}
# Flags whose next token is a value, not a position to sort.
VALUE_FLAGS = {
    "-o", "--output", "-oN", "-oX", "-oG", "-oA", "--output-file",
    "-w", "--wordlist", "-u", "--url", "-d", "--data", "-H", "--header",
    "-t", "--threads", "-p", "--ports", "-m", "--max-time", "-x", "--proxy",
    "-b", "--cookie", "-e", "--extensions", "-f", "--file", "-S",
    "--servername", "-c", "--config", "--target", "--workspace",
    "-X", "--request", "-A", "--user-agent", "-T", "--upload-file",
    "-F", "--form", "--data-binary", "--data-raw", "--data-urlencode",
    "--connect-timeout", "--retry", "--rate", "-r", "--range",
}
OUTPUT_FLAGS = {"-o", "--output", "-oN", "-oX", "-oG", "-oA", "--output-file"}
_SHELL_META = set("|;&<>`$(){}[]*?!")


def _canonical_command(command: str) -> str:
    """Best-effort argv canonicalization for dedup: aliases, output paths,
    and flag order. Values are kept attached to their flag; positionals stay
    in order. Shell syntax is only whitespace-normalized (never reordered)."""
    raw = command.strip()
    if not raw:
        return ""
    if any(ch in _SHELL_META for ch in raw):
        return " ".join(raw.split())
    try:
        import shlex
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    if not tokens:
        return ""
    exe, rest = tokens[0], tokens[1:]
    flags: list[tuple[str, str | None]] = []
    positionals: list[str] = []
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in OUTPUT_FLAGS and i + 1 < len(rest):
            i += 2
            continue
        if tok.startswith("--output=") or tok.startswith("--output-file="):
            i += 1
            continue
        tok = FLAG_ALIASES.get(tok, tok)
        if tok.startswith("-") and tok != "-":
            if tok in VALUE_FLAGS and i + 1 < len(rest):
                flags.append((tok, rest[i + 1]))
                i += 2
            else:
                flags.append((tok, None))
                i += 1
        else:
            positionals.append(tok)
            i += 1
    flags.sort(key=lambda fv: (fv[0], fv[1] or ""))
    parts = [exe]
    for flag, value in flags:
        parts.append(flag)
        if value is not None:
            parts.append(value)
    parts.extend(positionals)
    return " ".join(parts)


def _legacy_action_key(command: str) -> str:
    """Pre-canonicalization key: whitespace-only normalization. Kept so
    actions recorded by older runs remain deduplicable after the upgrade."""
    return hashlib.sha256(" ".join(command.split()).encode()).hexdigest()[:16]


def _action_key(command: str) -> str:
    """Normalize so near-duplicate commands (whitespace, flag order,
    aliases, transient output paths) still dedupe."""
    normalized = _canonical_command(command)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


@dataclass
class Hypothesis:
    id: str
    statement: str
    evidence: str = ""
    confidence: float = 0.5          # 0-1
    cost: float = 1.0                # relative effort to test; 1 = cheap
    test: str = ""
    status: str = "open"             # open | confirmed | refuted
    result: str = ""
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)

    def score(self) -> float:
        """Confidence-per-unit-cost: cheap, promising tests rank highest."""
        return self.confidence / max(self.cost, 0.1)


@dataclass
class ActionRecord:
    key: str
    command: str
    result_summary: str
    timestamp: float = field(default_factory=_now)


@dataclass
class FailedPath:
    description: str
    reason: str
    timestamp: float = field(default_factory=_now)


@dataclass
class Message:
    id: str
    from_agent: str
    to_agent: str             # a specific agent name, or "all" for broadcast
    msg_type: str             # info | finding | request | handoff | blocker | status
    text: str
    timestamp: float = field(default_factory=_now)
    read_by: list[str] = field(default_factory=list)
    hyp_id: str = ""          # §1.5 typed mailbox: exact filtering in HOT tier
    payload: dict = field(default_factory=dict)  # structured, compresses better than prose


class TargetState:
    """One instance per target workspace."""

    def __init__(self, state_file: Path):
        self.state_file = state_file
        self.action_log = state_file.parent / ACTION_LOG_DIR / ACTION_LOG_NAME
        self.target: str = ""
        self.mode: str = ""  # "htb" | "bugbounty"
        self.hypotheses: dict[str, Hypothesis] = {}
        self.actions: dict[str, ActionRecord] = {}
        self.failed_paths: list[FailedPath] = []
        self.milestones: dict[str, float] = {}
        self.messages: list[Message] = []
        self._next_msg_id: int = 1
        self.started_at: float = _now()
        # unknown top-level state.json keys, preserved verbatim across saves
        self.extra: dict = {}

    # ---- persistence ----

    @classmethod
    def load(cls, workspace, target: str = "", mode: str = "") -> "TargetState":
        workspace = Path(workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        state_file = workspace / "state.json"
        inst = cls(state_file)
        if state_file.exists():
            data = json.loads(state_file.read_text())
            inst.target = data.get("target") or target
            inst.mode = data.get("mode") or mode
            inst.started_at = data.get("started_at", _now())
            inst.milestones = data.get("milestones", {})
            inst.hypotheses = _coerce_dict(data.get("hypotheses", {}), Hypothesis)
            inst.actions = _coerce_dict(data.get("actions", {}), ActionRecord)
            inst.failed_paths = _coerce_list(data.get("failed_paths", []), FailedPath)
            inst.messages = _coerce_list(data.get("messages", []), Message)
            inst._next_msg_id = data.get("_next_msg_id", len(inst.messages) + 1)
            inst.extra = {k: v for k, v in data.items() if k not in KNOWN_KEYS}
        else:
            inst.target = target
            inst.mode = mode
        # The log is the full history; the snapshot only holds a tail.
        inst._load_action_log()
        return inst

    def save(self) -> None:
        snapshot_actions = self._actions_tail()
        data = {
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "milestones": self.milestones,
            "hypotheses": {k: asdict(v) for k, v in self.hypotheses.items()},
            "actions": {k: asdict(v) for k, v in snapshot_actions.items()},
            "failed_paths": [asdict(f) for f in self.failed_paths],
            "messages": [asdict(m) for m in self.messages],
            "_next_msg_id": self._next_msg_id,
        }
        # keys TargetState doesn't own survive the round-trip (setdefault:
        # the owned schema always wins if a key ever collides)
        for k, v in self.extra.items():
            data.setdefault(k, v)
        # atomic: readers never observe a partially-written file
        tmp = self.state_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, self.state_file)
        # Bound the append log without touching the hot path every action.
        self.compact_action_log(force=False)

    # ---- action log ----

    def _actions_tail(self) -> dict[str, ActionRecord]:
        if len(self.actions) <= ACTION_SNAPSHOT_LIMIT:
            return self.actions
        ordered = sorted(self.actions.values(),
                         key=lambda a: a.timestamp, reverse=True)
        return {a.key: a for a in ordered[:ACTION_SNAPSHOT_LIMIT]}

    def _load_action_log(self) -> None:
        if not self.action_log.exists():
            return
        try:
            lines = self.action_log.read_text(errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            if not isinstance(raw, dict):
                continue
            try:
                rec = ActionRecord(**raw)
            except TypeError:
                cmd = str(raw.get("command", ""))
                if not cmd:
                    continue
                rec = ActionRecord(
                    key=str(raw.get("key") or _action_key(cmd)),
                    command=cmd,
                    result_summary=str(raw.get("result_summary", ""))
                    or "free-form record - raw payload preserved",
                    timestamp=float(raw.get("timestamp") or _now()))
            if not rec.key:
                rec.key = _action_key(rec.command)
            # Snapshot wins for duplicate keys: it may carry a corrective
            # edit made without another append.
            self.actions.setdefault(rec.key, rec)

    def _append_action_log(self, record: ActionRecord) -> None:
        self.action_log.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(asdict(record), separators=(",", ":")) + "\n"
        lock_path = self.action_log.parent / ACTION_LOG_LOCK
        with open(lock_path, "a") as lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            fd = os.open(self.action_log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)

    def compact_action_log(self, force: bool = False) -> int:
        """Rewrite the JSONL log as one deduped line per action. Safe to
        call concurrently: all writers take .actions.lock and replace
        atomically. Returns the number of records kept."""
        if not force and not self.action_log.exists():
            return 0
        if not force:
            try:
                if self.action_log.stat().st_size < ACTION_LOG_COMPACT_BYTES:
                    return 0
            except OSError:
                return 0
        self.action_log.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.action_log.parent / ACTION_LOG_LOCK
        with open(lock_path, "a") as lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            # Merge what is already on disk under the lock: another writer
            # may have appended since this instance loaded. Compaction must
            # never drop a concurrent append.
            merged: dict[str, ActionRecord] = {}
            if self.action_log.exists():
                try:
                    lines = self.action_log.read_text(errors="replace").splitlines()
                except OSError:
                    lines = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(raw, dict):
                        continue
                    try:
                        rec = ActionRecord(**raw)
                    except TypeError:
                        cmd = str(raw.get("command", ""))
                        if not cmd:
                            continue
                        rec = ActionRecord(
                            key=str(raw.get("key") or _action_key(cmd)),
                            command=cmd,
                            result_summary=str(raw.get("result_summary", ""))
                            or "free-form record - raw payload preserved",
                            timestamp=float(raw.get("timestamp") or _now()))
                    if not rec.key:
                        rec.key = _action_key(rec.command)
                    merged.setdefault(rec.key, rec)
            # In-memory records win over an older duplicate on disk.
            merged.update(self.actions)
            ordered = sorted(merged.values(), key=lambda a: a.timestamp)
            tmp = self.action_log.with_suffix(".jsonl.tmp")
            with tmp.open("w") as fh:
                for rec in ordered:
                    fh.write(json.dumps(asdict(rec), separators=(",", ":")) + "\n")
            os.replace(tmp, self.action_log)
            self.actions = merged
        return len(ordered)

    # ---- action dedup ----

    def already_tried(self, command: str) -> Optional[ActionRecord]:
        hit = self.actions.get(_action_key(command))
        if hit is not None:
            return hit
        # Backward compatibility with actions written before argv
        # canonicalization: their keys hash only whitespace-collapsed text.
        return self.actions.get(_legacy_action_key(command))

    def record_action(self, command: str, result_summary: str) -> ActionRecord:
        key = _action_key(command)
        record = ActionRecord(key=key, command=command, result_summary=result_summary)
        self.actions[key] = record
        self._append_action_log(record)
        return record

    # ---- hypotheses ----

    def add_hypothesis(self, id: str, statement: str, evidence: str = "",
                        confidence: float = 0.5, cost: float = 1.0,
                        test: str = "") -> Hypothesis:
        h = Hypothesis(id=id, statement=statement, evidence=evidence,
                        confidence=confidence, cost=cost, test=test)
        self.hypotheses[id] = h
        return h

    def update_hypothesis(self, id: str, **kwargs) -> Hypothesis:
        h = self.hypotheses[id]
        for k, v in kwargs.items():
            setattr(h, k, v)
        h.updated_at = _now()
        return h

    def next_hypothesis(self) -> Optional[Hypothesis]:
        """Highest confidence/cost open hypothesis. Deliberately dumb and
        deterministic so it's cheap to call every turn instead of
        re-reasoning over the full hypothesis list in-context."""
        open_h = [h for h in self.hypotheses.values() if h.status == "open"]
        if not open_h:
            return None
        return max(open_h, key=lambda h: h.score())

    # ---- failed paths ----

    def mark_failed(self, description: str, reason: str) -> None:
        self.failed_paths.append(FailedPath(description=description, reason=reason))

    def is_known_failed(self, description: str) -> bool:
        norm = description.strip().lower()
        return any(norm in f.description.strip().lower() for f in self.failed_paths)

    # ---- mailbox (multi-agent coordination) ----

    def post_message(self, from_agent: str, to_agent: str, text: str,
                      msg_type: str = "info", hyp_id: str = "",
                      payload: dict | None = None) -> Message:
        msg = Message(id=f"m{self._next_msg_id}", from_agent=from_agent,
                       to_agent=to_agent, msg_type=msg_type, text=text,
                       hyp_id=hyp_id or "", payload=payload or {})
        self._next_msg_id += 1
        self.messages.append(msg)
        return msg

    def inbox(self, agent: str, unread_only: bool = True,
              msg_type: str | None = None, hyp_id: str | None = None
              ) -> list[Message]:
        """Messages addressed to `agent` directly, or broadcast to 'all'.
        Optional exact filters on the typed fields (§1.5)."""
        mine = [m for m in self.messages if m.to_agent in (agent, "all")]
        if unread_only:
            mine = [m for m in mine if agent not in m.read_by]
        if msg_type:
            mine = [m for m in mine if m.msg_type == msg_type]
        if hyp_id:
            mine = [m for m in mine if m.hyp_id == hyp_id]
        return sorted(mine, key=lambda m: m.timestamp)

    def mark_read(self, agent: str, msg_ids: list[str]) -> None:
        wanted = set(msg_ids)
        for m in self.messages:
            if m.id in wanted and agent not in m.read_by:
                m.read_by.append(agent)

    # ---- benchmark milestones ----

    def mark_milestone(self, name: str, at: Optional[float] = None,
                       force: bool = False) -> tuple[float, bool]:
        """name: 'first_path' | 'user' | 'root' | 'flag' | etc.

        Keep-first: once recorded, a later call is a no-op returning the
        existing elapsed time (use force=True to overwrite), so an
        accidental re-mark can't silently reset the benchmark clock.
        `at` is the absolute epoch the milestone actually happened at -
        for backfilling one that was noticed late. Returns
        (elapsed_since_started_at, was_newly_recorded)."""
        if name in self.milestones and not force:
            return self.milestones[name], False
        t = (at if at is not None else _now()) - self.started_at
        self.milestones[name] = t
        return t, True

    def benchmark_summary(self) -> dict:
        """Auto-derived fields only. Merge with the manually/LLM-judged
        quality scores (recon quality, reasoning quality, ...) from
        benchmark/README.md to fill out the full scorecard."""
        return {
            "target": self.target,
            "mode": self.mode,
            "unique_actions": len(self.actions),
            "hypotheses_total": len(self.hypotheses),
            "hypotheses_confirmed": sum(
                1 for h in self.hypotheses.values() if h.status == "confirmed"
            ),
            "hypotheses_refuted": sum(
                1 for h in self.hypotheses.values() if h.status == "refuted"
            ),
            "dead_ends": len(self.failed_paths),
            "time_to_first_path_s": self.milestones.get("first_path"),
            "time_to_user_s": self.milestones.get("user"),
            "time_to_root_s": self.milestones.get("root"),
            "time_to_flag_s": self.milestones.get("flag"),
        }


def _auto_validate_on_confirm(workspace: Path, hyp, state) -> None:
    """§3.5 synchronous validation: the moment a hypothesis flips to
    `confirmed`, create a finding skeleton (unless one already exists for the
    hypothesis) and run the deterministic gates on it immediately, so
    confirmed-but-unvalidated work is visible instead of silently sitting.

    Fail-open: when the full bb tree is not importable (state.py is copied
    standalone into smoke-test roots), this prints a manual-follow-up hint
    and changes nothing."""
    fdir = Path(workspace) / "findings"
    existing = None
    if fdir.is_dir():
        for p in sorted(fdir.glob("*.json")):
            try:
                d = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(d, dict) and (d.get("hypothesis_id") == hyp.id
                                        or d.get("id") == hyp.id):
                existing = d
                break
    if existing is None:
        fdir.mkdir(parents=True, exist_ok=True)
        skeleton = {
            "id": hyp.id, "hypothesis_id": hyp.id,
            "program": Path(workspace).name,
            "target": state.target or "", "endpoint": "", "method": "",
            "vuln_class": "", "summary": hyp.statement, "impact": "",
            "curl_poc": "", "evidence": [], "control_evidence": "",
            "reproduced": False, "deterministic": False, "not_documented": False,
            "identity_proven": False, "unrealistic_preconditions": False,
            "chain_proven": False, "skill_checked": False, "already_tried": False,
            "cheaper_test": "", "confirm_refute": hyp.test or "",
            "refute_plan": "", "status": "confirmed_unvalidated",
        }
        tmp = fdir / f"{hyp.id}.json.tmp"
        tmp.write_text(json.dumps(skeleton, indent=2) + "\n")
        os.replace(tmp, fdir / f"{hyp.id}.json")
        print(f"auto: finding skeleton findings/{hyp.id}.json created "
              f"(confirmed_unvalidated) — attach evidence, then `bb validate {hyp.id}`")
    else:
        print(f"auto: existing finding for {hyp.id} — run `bb validate {hyp.id}`")

    try:
        root = Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from lib.bb import validate as bb_validate
        f = json.loads((fdir / f"{hyp.id}.json").read_text())
        payload = bb_validate.validate(f, workspace=Path(workspace), base=root,
                                       write=False)
        failed = [f"gate{g['n']}_{g['name']}" for g in payload.get("gates", [])
                  if not g["pass"]]
        state.extra["bb_last_validation"] = {
            "hypothesis_id": hyp.id, "finding_id": hyp.id,
            "status": payload.get("status"), "failed_gates": failed,
            "at": time.time()}
        state.post_message(
            "state", "critic-agent",
            f"{hyp.id} confirmed -> findings/{hyp.id}.json; auto-gates: "
            f"{'PASS' if not failed else 'FAIL ' + ','.join(failed)}; "
            f"attach evidence then `bb validate {hyp.id}`", "request")
        state.save()
    except Exception as exc:  # standalone state.py: validation is a manual step
        print(f"auto-validate unavailable ({exc}) — run `bb validate {hyp.id}` manually")


def _validate_mutation(cmd: str, args) -> str:
    """Strict checks at the CLI boundary. Unknown keys are the state loader's
    problem; known fields must be the right type/range before any save."""
    if cmd in ("add-hyp", "update-hyp"):
        conf = getattr(args, "confidence", None)
        if conf is not None:
            try:
                conf = float(conf)
            except (TypeError, ValueError):
                return f"confidence must be numeric, got {conf!r}"
            if not 0.0 <= conf <= 1.0 or conf != conf:
                return f"confidence must be in [0,1], got {conf}"
        cost = getattr(args, "cost", None)
        if cost is not None:
            try:
                cost = float(cost)
            except (TypeError, ValueError):
                return f"cost must be numeric, got {cost!r}"
            if cost < 0 or cost != cost or cost == float("inf"):
                return f"cost must be a finite value >= 0, got {cost}"
        status = getattr(args, "status", None)
        if status is not None and status not in ("open", "confirmed", "refuted"):
            return f"status must be open|confirmed|refuted, got {status!r}"
    if cmd == "record-action":
        if not (args.cmd or "").strip():
            return "record-action --cmd must not be empty"
        if not (args.result or "").strip():
            return "record-action --result must not be empty"
    if cmd == "post-msg":
        if not (args.text or "").strip():
            return "post-msg --text must not be empty"
        if not args.from_agent.strip() or not args.to_agent.strip():
            return "post-msg --from/--to must not be empty"
    if cmd == "mark-failed":
        if not (args.desc or "").strip() or not (args.reason or "").strip():
            return "mark-failed --desc/--reason must not be empty"
    if cmd == "mark-milestone":
        if args.at is not None and args.at < 0:
            return "mark-milestone --at must be a positive epoch"
    if cmd == "set-target" and not (args.target or "").strip():
        return "set-target --target must not be empty"
    return ""


def _cli():
    p = argparse.ArgumentParser(
        description="State/hypothesis/mailbox CLI for agentic-bug-hunter specialists.")
    p.add_argument("workspace", help="e.g. labs/HTB/machines/cap")
    # dest is "subcmd", not "cmd" - the already-tried/record-action
    # subcommands each define their own --cmd flag, and argparse puts every
    # parsed value into one flat namespace, so dest="cmd" here would get
    # silently clobbered by --cmd's value and break dispatch with no error.
    sub = p.add_subparsers(dest="subcmd", required=False)

    sp = sub.add_parser("set-target", help="bootstrap workspace metadata (creates state.json so dashboards/drivers can see the run)")
    sp.add_argument("--target", required=True)
    sp.add_argument("--mode", default="htb", choices=["htb", "bugbounty"])

    sp = sub.add_parser("benchmark", help="print the auto-derived benchmark summary (default)")

    sp = sub.add_parser("post-msg", help="post a mailbox message")
    sp.add_argument("--from", dest="from_agent", required=True)
    sp.add_argument("--to", dest="to_agent", required=True, help="agent name, or 'all'")
    sp.add_argument("--type", dest="msg_type", default="info",
                     choices=["info", "finding", "request", "handoff",
                              "blocker", "status"])
    sp.add_argument("--text", required=True)
    sp.add_argument("--hyp-id", dest="hyp_id", default="",
                    help="tie the message to a hypothesis (typed filtering)")
    sp.add_argument("--payload", default=None,
                    help="JSON object carried verbatim (typed mailbox §1.5)")

    sp = sub.add_parser("inbox", help="read a mailbox")
    sp.add_argument("--for", dest="agent", required=True)
    sp.add_argument("--all", action="store_true", help="include already-read messages")
    sp.add_argument("--type", dest="msg_type", default=None,
                    help="exact msg_type filter (typed mailbox §1.5)")
    sp.add_argument("--hyp-id", dest="hyp_id", default=None,
                    help="exact hypothesis filter")
    sp.add_argument("--full", action="store_true",
                    help="print full message text (default: 400-char preview)")
    sp.add_argument("--mark-read", nargs="*", default=None, metavar="MSG_ID",
                     help="mark these message ids read for this agent after printing")

    sp = sub.add_parser("history", help="print one hypothesis and related mail (COLD context)")
    sp.add_argument("--hyp", required=True, help="hypothesis id, e.g. h7")

    sp = sub.add_parser("add-hyp", help="add a hypothesis")
    sp.add_argument("--id", required=True)
    sp.add_argument("--statement", required=True)
    sp.add_argument("--evidence", default="")
    sp.add_argument("--confidence", type=float, default=0.5)
    sp.add_argument("--cost", type=float, default=1.0)
    sp.add_argument("--test", default="")

    sp = sub.add_parser("next-hyp", help="print the highest-ranked open hypothesis")

    sp = sub.add_parser("update-hyp", help="update a hypothesis's status/result/cost/confidence")
    sp.add_argument("--id", required=True)
    sp.add_argument("--status", choices=["open", "confirmed", "refuted"])
    sp.add_argument("--result", default=None)
    # Calibration hook for `bb next-hyp --apply`: lets the deterministic ranking
    # use benchmark-derived costs instead of a flat 1.0 for every hypothesis.
    sp.add_argument("--cost", type=float, default=None)
    sp.add_argument("--confidence", type=float, default=None)

    sp = sub.add_parser("set-extra", help="set an auxiliary top-level state key (preserved verbatim)")
    sp.add_argument("--key", required=True)
    sp.add_argument("--value", required=True,
                    help="JSON value when parseable, otherwise a plain string")

    sp = sub.add_parser("get-extra", help="print an auxiliary top-level state key")
    sp.add_argument("--key", required=True)

    sp = sub.add_parser("already-tried", help="check if a command was already run")
    sp.add_argument("--cmd", required=True)

    sp = sub.add_parser("record-action", help="record a command + its result")
    sp.add_argument("--cmd", required=True)
    sp.add_argument("--result", required=True)

    sp = sub.add_parser("mark-failed", help="record a dead end")
    sp.add_argument("--desc", required=True)
    sp.add_argument("--reason", required=True)

    sp = sub.add_parser("is-known-failed", help="check if a technique is a known dead end")
    sp.add_argument("--desc", required=True)

    sp = sub.add_parser("mark-milestone", help="record a benchmark milestone")
    sp.add_argument("--name", required=True, help="e.g. user, root, flag, first_path")
    sp.add_argument("--at", type=float, default=None, metavar="EPOCH",
                     help="absolute epoch it actually happened (late backfill)")
    sp.add_argument("--force", action="store_true",
                     help="overwrite an already-recorded milestone")

    args = p.parse_args()
    cmd = args.subcmd or "benchmark"

    # inbox is read-only UNLESS --mark-read was given (it mutates read_by)
    mutating = cmd in MUTATING_CMDS or (cmd == "inbox" and args.mark_read is not None)
    if mutating:
        # serialize the whole load->mutate->save window across concurrent
        # specialists; a blocking acquire is correct here - the holder is
        # a fast, bounded CLI command
        lock_path = Path(args.workspace) / ".state.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a") as _lockfd:
            fcntl.flock(_lockfd.fileno(), fcntl.LOCK_EX)
            _run_command(args, cmd)
    else:
        _run_command(args, cmd)


def _run_command(args, cmd: str) -> None:
    if cmd in MUTATING_CMDS:
        reason = _validate_mutation(cmd, args)
        if reason:
            _reject(args.workspace, cmd, vars(args), reason)
    state = TargetState.load(args.workspace)

    if cmd == "set-target":
        state.target = args.target
        state.mode = args.mode
        state.save()
        print(f"target={args.target} mode={args.mode}")

    if cmd == "benchmark":
        print(json.dumps(state.benchmark_summary(), indent=2))
        return

    if cmd == "post-msg":
        payload = {}
        if args.payload:
            try:
                payload = json.loads(args.payload)
            except (ValueError, TypeError):
                _reject(args.workspace, cmd, vars(args),
                        "--payload must be a JSON object")
        if not isinstance(payload, dict):
            _reject(args.workspace, cmd, vars(args), "--payload must be a JSON object")
        msg = state.post_message(args.from_agent, args.to_agent, args.text,
                                 args.msg_type, hyp_id=args.hyp_id,
                                 payload=payload)
        state.save()
        print(f"posted {msg.id}: {args.from_agent} -> {args.to_agent} [{args.msg_type}]"
              + (f" hyp={msg.hyp_id}" if msg.hyp_id else ""))

    elif cmd == "inbox":
        msgs = state.inbox(args.agent, unread_only=not args.all,
                           msg_type=args.msg_type, hyp_id=args.hyp_id)
        for m in msgs:
            text = m.text if args.full else m.text[:400]
            suffix = "" if args.full or len(m.text) <= 400 else " … (--full for rest)"
            tag = m.msg_type + (f":{m.hyp_id}" if m.hyp_id else "")
            print(f"[{m.id}] {m.from_agent} -> {m.to_agent} ({tag}): {text}{suffix}")
        if not msgs:
            print("(empty)")
        if args.mark_read:
            state.mark_read(args.agent, args.mark_read)
            state.save()

    elif cmd == "history":
        h = state.hypotheses.get(args.hyp)
        if h is None:
            print(f"(unknown hypothesis {args.hyp})")
            return
        print(json.dumps(asdict(h), indent=2))
        related = [m for m in state.messages if args.hyp in m.text]
        if related:
            print("\nrelated mail:")
            for m in related:
                print(f"  [{m.id}] {m.from_agent} -> {m.to_agent}: {m.text}")
        print(f"\nfull board: bb state {args.workspace} benchmark")

    elif cmd == "add-hyp":
        h = state.add_hypothesis(args.id, args.statement, evidence=args.evidence,
                                  confidence=args.confidence, cost=args.cost, test=args.test)
        state.save()
        print(f"added {h.id} (score={h.score():.2f})")

    elif cmd == "next-hyp":
        h = state.next_hypothesis()
        print(json.dumps(asdict(h), indent=2) if h else "(no open hypotheses)")

    elif cmd == "update-hyp":
        kwargs = {}
        if args.status:
            kwargs["status"] = args.status
        if args.result is not None:
            kwargs["result"] = args.result
        if args.cost is not None:
            kwargs["cost"] = args.cost
        if args.confidence is not None:
            kwargs["confidence"] = args.confidence
        if args.id not in state.hypotheses:
            _reject(args.workspace, cmd, vars(args),
                    f"unknown hypothesis id {args.id!r}")
        h = state.update_hypothesis(args.id, **kwargs)
        state.save()
        print(f"updated {h.id}: status={h.status}")
        if h.status == "confirmed":
            _auto_validate_on_confirm(args.workspace, h, state)

    elif cmd == "set-extra":
        try:
            value = json.loads(args.value)
        except (ValueError, TypeError):
            value = args.value
        state.extra[args.key] = value
        state.save()
        print(f"set {args.key}")

    elif cmd == "get-extra":
        if args.key not in state.extra:
            print("(unset)")
        else:
            print(json.dumps(state.extra[args.key], indent=2, default=str)
                  if not isinstance(state.extra[args.key], str)
                  else state.extra[args.key])

    elif cmd == "already-tried":
        rec = state.already_tried(args.cmd)
        print(json.dumps(asdict(rec), indent=2) if rec else "(not tried before)")

    elif cmd == "record-action":
        rec = state.record_action(args.cmd, args.result)
        state.save()
        print(f"recorded action {rec.key}")

    elif cmd == "mark-failed":
        state.mark_failed(args.desc, args.reason)
        state.save()
        print("recorded dead end")

    elif cmd == "is-known-failed":
        print("yes" if state.is_known_failed(args.desc) else "no")

    elif cmd == "mark-milestone":
        t, fresh = state.mark_milestone(args.name, at=args.at, force=args.force)
        if not fresh:
            print(f"{args.name} already recorded at {t:.2f}s - not overwritten "
                  f"(use --force to replace)")
            return
        state.save()
        print(f"{args.name} at {t:.2f}s")


if __name__ == "__main__":
    _cli()
