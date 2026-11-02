#!/usr/bin/env python3
"""Live monitoring + control dashboard for `bb` runs.

Tabs:
  Monitor  hypotheses (ranked exactly as `next-hyp` will pick), stats, warnings,
           mailbox, dead ends, heartbeat.
  Timeline chronological feed of every action, mailbox message, hypothesis
           change, and milestone — built from state.json, no extra storage.
  Control  steer an agent (mailbox message) + pause-after-current-turn.
  Learn    run writeups/reports/skills + learn-candidates with approve buttons.

stdlib only. Binds to 127.0.0.1 by default: targets, findings, and credentials
referenced in mailbox messages must not be reachable from the network.

Long-poll (`/api/state?...&since=VERSION`) is used instead of a 3-second
refresh, so the live feel does not require constant polling.

    python3 scripts/dashboard.py --port 8765
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.state import TargetState  # noqa: E402
from lib.bb import config, learn, leads, priors, statex  # noqa: E402

STEER_AGENTS = sorted({
    "all", "orchestrator", "critic-agent", "recon-agent", "web-agent",
    "ad-agent", "privesc-agent", "linux-privesc-agent",
})
STEER_TYPES = {"info", "request", "handoff"}
POLL_SECONDS = 20.0


def discover_workspaces(root: Path) -> list[Path]:
    return config.discover_workspaces(root)


def _version(root: Path, ws: Path) -> str:
    parts = []
    for p in (ws / "state.json", ws / "state" / "actions.jsonl",
              ws / "agent_logs" / "turns.jsonl", ws / "agent_logs" / "gates.jsonl",
              ws / ".ratelimit.json", ws / "learn-candidates.json", ws / "leads.jsonl"):
        try:
            st = p.stat()
            parts.append(f"{st.st_mtime_ns}:{st.st_size}")
        except OSError:
            parts.append("0")
    return "|".join(parts)


def build_timeline(state, limit: int = 250) -> list[dict]:
    ev = []
    for a in state.actions.values():
        ev.append({"t": a.timestamp, "kind": "action", "who": "action",
                   "text": f"$ {a.command}  →  {a.result_summary}"})
    for m in state.messages:
        ev.append({"t": m.timestamp, "kind": "msg", "who": f"{m.from_agent} → {m.to_agent}",
                   "text": f"[{m.msg_type}] {m.text}"})
    for h in state.hypotheses.values():
        ev.append({"t": h.created_at, "kind": "hypothesis", "who": h.id,
                   "text": f"created: {h.statement}"})
        if h.updated_at and h.updated_at > h.created_at + 0.001:
            ev.append({"t": h.updated_at, "kind": "hypothesis", "who": h.id,
                       "text": f"{h.status}: {h.result or h.statement}"})
    for name, elapsed in state.milestones.items():
        ev.append({"t": state.started_at + float(elapsed), "kind": "milestone",
                   "who": name, "text": f"milestone recorded at {float(elapsed):.1f}s"})
    ev.sort(key=lambda e: e["t"], reverse=True)
    return [{"t": e["t"], "kind": e["kind"], "who": e["who"], "text": e["text"][:600]}
            for e in ev[:limit]]


def _tail_jsonl(path: Path, limit: int = 40) -> list[dict]:
    try:
        lines = path.read_text(errors="ignore").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def agent_statuses(ws: Path, state, tokens: dict, sessions: dict,
                   adaptive: dict, turns: list[dict],
                   failures: list[dict]) -> dict:
    """Best-effort per-specialist state for the dashboard.

    Sources are append-only turn events, critic-gate verdicts, crash memory,
    and the live limiter cooldown. A BLOCK is shown until that agent's next
    turn_end; a stale turn_start becomes stuck rather than running forever.
    """
    now = time.time()
    known = list(dict.fromkeys([
        *config.ROLE_SPECIALISTS, "critic-agent",
        *sessions.keys(), *((tokens or {}).get("agents") or {}).keys(),
    ]))
    latest: dict[str, tuple[float, str, str]] = {}

    def put(agent: str, ts: float, status: str, why: str) -> None:
        if not agent:
            return
        cur = latest.get(agent)
        if cur is None or ts >= cur[0]:
            latest[agent] = (ts, status, why)

    for t in turns:
        ts = float(t.get("ts") or 0)
        agent = t.get("agent") or ""
        if t.get("event") == "turn_start":
            put(agent, ts, "running", "turn started")
        elif t.get("event") == "turn_end":
            err = (t.get("error") or "").strip()
            if t.get("ok"):
                put(agent, ts, "idle", "last turn ok")
            else:
                put(agent, ts, "stuck", err[:160] or "last turn failed")

    for g in _tail_jsonl(ws / "agent_logs" / "gates.jsonl", 400):
        if g.get("verdict") != "BLOCK":
            continue
        put(g.get("agent") or "", float(g.get("ts") or 0), "blocked-by-critic",
            (g.get("reason") or g.get("command") or "critic BLOCK")[:160])

    for f in failures:
        put(f.get("agent") or "", float(f.get("epoch") or 0), "stuck",
            (f.get("reason") or "failure")[:160])

    cooldown = max(0.0, float((adaptive or {}).get("cooldown_until", 0) or 0) - now)
    out = {}
    for agent in known:
        ts, status, why = latest.get(agent, (0.0, "idle", "no turn yet"))
        if status == "running" and ts and now - ts > 900:
            status = "stuck"
            why = f"turn started {int((now - ts) // 60)}m ago"
        if cooldown > 0 and status == "idle":
            status = "rate-limited"
            why = f"limiter cooldown {cooldown:.0f}s"
        out[agent] = {"status": status, "why": why, "last_event": ts}
    return out


def workspace_summary(ws: Path, root: Path) -> dict:
    state = TargetState.load(ws)
    ranked = priors.adjusted(state)
    recent_messages = sorted(state.messages, key=lambda m: m.timestamp, reverse=True)[:15]
    recent_actions = sorted(state.actions.values(), key=lambda a: a.timestamp, reverse=True)[:10]
    hb = statex.last_active(ws)
    interrupted, why = statex.is_interrupted(ws)
    tokens = statex.token_summary(ws)
    adaptive = (config.read_json(ws / ".ratelimit.json", default={}) or {}).get("_adaptive") or {}
    turns = _tail_jsonl(ws / "agent_logs" / "turns.jsonl")
    sessions = statex.get_sessions(ws)
    return {
        "path": config.rel(ws, root),
        "version": _version(root, ws),
        "started_at": state.started_at,
        "milestones": state.milestones,
        "benchmark": state.benchmark_summary(),
        "hypotheses": [asdict(h) for h in sorted(
            state.hypotheses.values(), key=lambda h: h.updated_at, reverse=True)],
        "ranked": ranked,
        "messages": [asdict(m) for m in recent_messages],
        "failed_paths": [asdict(f) for f in state.failed_paths],
        "recent_actions": [
            {"command": a.command, "result": a.result_summary, "timestamp": a.timestamp}
            for a in recent_actions
        ],
        "timeline": build_timeline(state),
        "tokens": tokens,
        "sessions": sessions,
        "adaptive": adaptive,
        "turns": turns,
        "agent_status": agent_statuses(ws, state, tokens, sessions,
                                       adaptive, turns, statex.failures(ws)),
        "paused": statex.pause_requested(ws),
        "heartbeat": hb,
        "warnings": statex.warnings(ws),
        "interrupted": interrupted,
        "interrupted_reason": why,
    }


def learn_files(root: Path) -> list[dict]:
    docs = []
    for ws in discover_workspaces(root):
        for name in ("writeup.md", "WRITEUP.md", "postmortem.md"):
            f = ws / name
            if f.exists():
                docs.append({"title": f"{ws.name}: {name.replace('.md', '')}",
                             "kind": "run writeup", "path": config.rel(f, root)})
    for base, kind in (("skills", "learned skill"), ("findings", "engagement report")):
        d = root / base
        if d.is_dir():
            for md in sorted(d.rglob("*.md"))[:600]:
                docs.append({"title": f"{md.parent.name}/{md.name}",
                             "kind": kind, "path": config.rel(md, root)})
    return docs


def doc_content(root: Path, src: str) -> bytes | None:
    p = (root / src).resolve()
    if not str(p).startswith(str(root.resolve()) + "/") or p.suffix != ".md":
        return None
    if not p.is_file():
        return None
    return p.read_bytes()[:200_000]


PAGE = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>bb monitor</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0d1117; color:#c9d1d9; font-family: ui-monospace, "SF Mono", Menlo, monospace;
         margin:0; padding:20px; }
  h1 { font-size:16px; color:#58a6ff; margin:0 0 16px; }
  .targets { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }
  .target-btn { background:#161b22; border:1px solid #30363d; color:#c9d1d9; padding:6px 12px;
                border-radius:6px; cursor:pointer; font-size:13px; }
  .target-btn.active { border-color:#58a6ff; color:#58a6ff; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(110px,1fr)); gap:10px; margin-bottom:16px; }
  .stat { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px; }
  .stat .n { font-size:20px; font-weight:600; }
  .stat .l { font-size:11px; color:#8b949e; text-transform:uppercase; }
  table { width:100%; border-collapse: collapse; font-size:13px; margin-bottom:16px; }
  th { text-align:left; color:#8b949e; font-weight:500; font-size:11px; text-transform:uppercase;
       border-bottom:1px solid #30363d; padding:6px 8px; }
  td { padding:6px 8px; border-bottom:1px solid #21262d; vertical-align:top; }
  .status-open { color:#d29922; } .status-confirmed { color:#3fb950; } .status-refuted { color:#f85149; }
  .agent-running { color:#58a6ff; } .agent-idle { color:#8b949e; }
  .agent-blocked-by-critic { color:#d29922; } .agent-rate-limited { color:#d29922; }
  .agent-stuck { color:#f85149; }
  .section-title { font-size:12px; color:#8b949e; text-transform:uppercase; margin:20px 0 8px; }
  .msg-type-finding { color:#3fb950; } .msg-type-handoff { color:#58a6ff; }
  .msg-type-info { color:#8b949e; } .msg-type-request { color:#d29922; }
  .empty { color:#8b949e; font-style:italic; padding:8px; }
  .score { color:#8b949e; font-size:11px; }
  #feed { border:1px solid #30363d; border-radius:6px; background:#0f1620; padding:8px; }
  .feedrow { display:flex; gap:10px; padding:4px 6px; border-bottom:1px solid #1a2330; font-size:12px; align-items:baseline; }
  .feedrow:last-child { border-bottom:none; }
  .ago { color:#8b949e; font-size:10px; min-width:64px; text-align:right; flex-shrink:0; }
  .feedrow span:nth-child(2) { min-width:170px; flex-shrink:0; }
  .feedrow span:last-child { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .tabs { display:flex; gap:6px; margin:10px 0 14px; flex-wrap:wrap; }
  .tab { background:#161b22; border:1px solid #30363d; color:#c9d1d9; padding:7px 18px;
         border-radius:6px; cursor:pointer; font-size:13px; font-family:inherit; }
  .tab.active { border-color:#58a6ff; color:#58a6ff; }
  .formrow { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:8px; }
  select, textarea, .btn { background:#161b22; color:#c9d1d9; border:1px solid #30363d;
         border-radius:6px; padding:6px 10px; font:inherit; font-size:13px; }
  .btn { cursor:pointer; border-color:#2a6099; color:#58a6ff; }
  .btn:hover { background:#1f2937; }
  .btn.warn { border-color:#9e6a03; color:#d29922; }
  .btn.good { border-color:#238636; color:#3fb950; }
  textarea { width:100%; box-sizing:border-box; resize:vertical; }
  #steer-status, #pause-status { font-size:11px; color:#8b949e; }
  #steer-status.ok { color:#3fb950; } #steer-status.err { color:#f85149; }
  .learnwrap { display:grid; grid-template-columns: 300px 1fr; gap:14px; align-items:start; }
  .learnlist { border:1px solid #30363d; border-radius:6px; max-height:70vh; overflow:auto; }
  .learnitem { padding:7px 10px; border-bottom:1px solid #21262d; cursor:pointer; font-size:12px; }
  .learnitem:hover { background:#161b22; }
  .learnitem.active { background:#161b22; border-left:2px solid #58a6ff; }
  .learnitem .kind { color:#8b949e; font-size:10px; text-transform:uppercase; display:block; }
  .learndoc { border:1px solid #30363d; border-radius:6px; padding:14px 18px;
              max-height:70vh; overflow:auto; font-size:13px; line-height:1.55; }
  .learndoc h1,.learndoc h2,.learndoc h3 { color:#58a6ff; margin:14px 0 6px; }
  .learndoc h1 { font-size:17px; } .learndoc h2 { font-size:15px; } .learndoc h3 { font-size:14px; }
  .learndoc code { background:#161b22; border:1px solid #30363d; border-radius:4px; padding:1px 5px; font-size:12px; }
  .learndoc pre { background:#0f1620; border:1px solid #30363d; border-radius:6px;
                  padding:10px; overflow:auto; white-space:pre-wrap; }
  .learndoc pre code { background:none; border:none; }
  .learndoc a { color:#58a6ff; }
  .learndoc li { margin-left:18px; }
  .warnbox { border:1px solid #9e6a03; background:#2a210f; color:#d29922; border-radius:6px;
             padding:8px 12px; font-size:12px; margin-bottom:12px; }
  .pause-on { color:#d29922; }
</style>
</head>
<body>
  <h1>bb monitor <span id="pulse" style="color:#3fb950;font-size:11px;"></span></h1>
<div class="tabs">
  <button class="tab active" id="tabbtn-monitor" onclick="switchTab('monitor')">Monitor</button>
  <button class="tab" id="tabbtn-timeline" onclick="switchTab('timeline')">Timeline</button>
  <button class="tab" id="tabbtn-control" onclick="switchTab('control')">Control</button>
  <button class="tab" id="tabbtn-learn" onclick="switchTab('learn')">Learn</button>
</div>
<div class="targets" id="targets"></div>
<div id="warnbar"></div>

<div id="pane-monitor">
  <div id="content"><div class="empty">loading...</div></div>
  <div class="section-title">live activity feed (actions + mailbox, newest first)</div>
  <div id="feed"><div class="empty">loading...</div></div>
</div>

<div id="pane-timeline" style="display:none">
  <div class="formrow">
    <label>filter</label>
    <select id="timeline-filter" onchange="renderTimeline()">
      <option value="">all events</option>
      <option value="action">actions</option>
      <option value="msg">mailbox</option>
      <option value="hypothesis">hypotheses</option>
      <option value="milestone">milestones</option>
    </select>
    <span id="timeline-count" class="score"></span>
  </div>
  <div id="timeline"><div class="empty">loading...</div></div>
</div>

<div id="pane-control" style="display:none">
  <div class="section-title">run control</div>
  <div class="formrow">
    <button class="btn warn" id="pause-btn" onclick="togglePause()">pause after current turn</button>
    <span id="pause-status"></span>
  </div>
  <div class="section-title">steer an agent — lands in its mailbox; it acts next turn and results flow back</div>
  <div class="formrow">
    <label>to</label><select id="steer-to"></select>
    <label>type</label><select id="steer-type-choice"></select>
    <button class="btn" onclick="sendSteer()">send instruction</button>
    <span id="steer-status"></span>
  </div>
  <textarea id="steer-text" rows="5"
    placeholder="Message to the agent, e.g.&#10;'hypothesis h7 looks wrong - SSH banner says OpenSSH 9.x, re-check the JotForm CVE instead'&#10;Finish with: when done, update the hypothesis and post a reply to all."></textarea>
  <div class="section-title">claim a lead you are working by hand — specialists will skip it (§3.6)</div>
  <div class="formrow">
    <label>lead id</label><input id="claim-lead-id" size="12" placeholder="lb-xxxxxx">
    <button class="btn" onclick="claimLead()">claim as operator</button>
    <span id="claim-status"></span>
  </div>
  <div class="section-title">what the agents said</div>
  <div id="replies"><div class="empty">loading...</div></div>
</div>

<div id="pane-learn" style="display:none">
  <div class="section-title">learn candidates (approve before commit — nothing auto-commits)</div>
  <div id="candidates"><div class="empty">loading...</div></div>
  <div class="learnwrap">
    <div id="learn-list" class="learnlist"><div class="empty">loading...</div></div>
    <div id="learn-doc" class="learndoc"><div class="empty">pick a writeup, report or skill on the left</div></div>
  </div>
</div>

<script>
let current = null;
let stateVersion = "";
let lastState = null;
let pollGen = 0;
const STEER_AGENTS = ["all","orchestrator","critic-agent","recon-agent","web-agent","ad-agent","privesc-agent","linux-privesc-agent"];
const STEER_TYPES = ["request","info","handoff"];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const enc = encodeURIComponent;

function switchTab(t) {
  ['monitor','timeline','control','learn'].forEach(n => {
    document.getElementById('pane-'+n).style.display = (n===t ? '' : 'none');
    document.getElementById('tabbtn-'+n).classList.toggle('active', n===t);
  });
  if (t === 'control') refreshControl();
  if (t === 'learn') { loadLearnIndex(); loadCandidates(); }
  if (t === 'timeline') renderTimeline();
}

/* ---- monitor ---- */
function fmtTime(s) { return (s===null||s===undefined) ? '-' : s.toFixed(1)+'s'; }
function fmtK(n) {
  n = Number(n || 0);
  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';
  if (n >= 1e3) return (n/1e3).toFixed(1)+'k';
  return String(n);
}
function stat(n, label) { return `<div class="stat"><div class="n">${n}</div><div class="l">${label}</div></div>`; }
function esc(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
function ago(ts) {
  const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}
function renderWarnings(data) {
  const el = document.getElementById('warnbar');
  const ws = (data.warnings || []).slice();
  if (data.interrupted) ws.unshift('interrupted: ' + data.interrupted_reason);
  if (data.paused) ws.unshift('pause sentinel set — the orchestrator will stop after the current turn');
  el.innerHTML = ws.length ? ws.map(w => `<div class="warnbox">⚠ ${esc(w)}</div>`).join('') : '';
}
function renderMonitor(data) {
  lastState = data;
  const b = data.benchmark;
  document.getElementById('pulse').textContent = '● live ' + new Date().toLocaleTimeString();
  let html = '<div class="grid">';
  html += stat(b.unique_actions, 'actions');
  html += stat(b.hypotheses_total, 'hypotheses');
  html += stat(b.hypotheses_confirmed, 'confirmed');
  html += stat(b.hypotheses_refuted, 'refuted');
  html += stat(b.dead_ends, 'dead ends');
  html += stat(fmtTime(b.time_to_user_s), 'time to user');
  html += stat(fmtTime(b.time_to_root_s), 'time to root');
  html += stat(fmtTime(b.time_to_flag_s), 'time to flag');
  const tk = data.tokens || {}; const tkTotal = (tk.total || {}).total || 0;
  html += stat(fmtK(tkTotal), 'tokens');
  html += stat('$' + Number(tk.cost || 0).toFixed(2), 'model cost');
  html += stat(tk.turns || 0, 'turns');
  html += stat((data.adaptive || {}).parallel ?? '-', 'parallel slots');
  html += '</div>';

  html += '<div class="section-title">ranked open hypotheses — this is exactly what next-hyp will pick</div>';
  const ranked = data.ranked || [];
  if (!ranked.length) html += '<div class="empty">no open hypotheses</div>';
  else {
    html += '<table><tr><th>#</th><th>id</th><th>score</th><th>conf</th><th>stored</th><th>effective</th><th>category</th><th>statement</th></tr>';
    ranked.forEach((h,i) => {
      html += `<tr><td>${i+1}</td><td>${esc(h.id)}</td><td class="score">${h.score.toFixed(2)}</td>` +
        `<td>${h.confidence.toFixed(2)}</td><td class="score">${h.cost.toFixed(2)}</td>` +
        `<td>${h.effective_cost.toFixed(2)}</td><td class="score">${esc(h.category)}</td>` +
        `<td>${esc((h.statement||'').slice(0,140))}</td></tr>`;
    });
    html += '</table>';
  }

  html += '<div class="section-title">all hypotheses (most recently updated first)</div>';
  if (!data.hypotheses.length) html += '<div class="empty">none yet</div>';
  else {
    html += '<table><tr><th>id</th><th>status</th><th>statement</th><th>result</th></tr>';
    data.hypotheses.forEach(h => {
      html += `<tr><td>${esc(h.id)}</td><td class="status-${h.status}">${h.status}</td>` +
        `<td>${esc(h.statement)}</td><td>${esc(h.result || '-')}</td></tr>`;
    });
    html += '</table>';
  }

  html += '<div class="section-title">dead ends</div>';
  if (!data.failed_paths.length) html += '<div class="empty">none recorded</div>';
  else {
    html += '<table><tr><th>technique</th><th>reason</th></tr>';
    data.failed_paths.forEach(f => html += `<tr><td>${esc(f.description)}</td><td>${esc(f.reason)}</td></tr>`);
    html += '</table>';
  }

  html += '<div class="section-title">specialists — round-robin status, session, tokens, active model time</div>';
  const byAgent = (data.tokens || {}).agents || {};
  const sessions = data.sessions || {};
  const statuses = data.agent_status || {};
  const agents = Array.from(new Set([...Object.keys(statuses), ...Object.keys(byAgent), ...Object.keys(sessions)])).sort();
  if (!agents.length) html += '<div class="empty">no turns recorded yet</div>';
  else {
    html += '<table><tr><th>agent</th><th>status</th><th>why</th><th>session</th><th>turns</th><th>tokens</th><th>active</th><th>cost</th></tr>';
    agents.forEach(a => {
      const t = byAgent[a] || {};
      const st = statuses[a] || {status:'idle', why:'no turn yet'};
      const sess = sessions[a] ? sessions[a].slice(0,18)+'…' : '-';
      html += `<tr><td>${esc(a)}</td>` +
        `<td class="agent-${esc(st.status)}">${esc(st.status)}</td>` +
        `<td class="score">${esc(st.why || '')}</td>` +
        `<td class="score">${esc(sess)}</td>` +
        `<td>${t.turns || 0}</td><td>${fmtK((t.tokens||{}).total)}</td>` +
        `<td>${fmtTime(t.duration || 0)}</td><td>$${Number(t.cost||0).toFixed(2)}</td></tr>`;
    });
    html += '</table>';
  }

  html += '<div class="section-title">turn stream — append-only agent_logs/turns.jsonl (newest last)</div>';
  const turns = data.turns || [];
  if (!turns.length) html += '<div class="empty">no turn events yet</div>';
  else {
    html += '<table><tr><th>when</th><th>event</th><th>agent</th><th>round</th><th>detail</th></tr>';
    turns.slice(-14).forEach(t => {
      let detail = '';
      if (t.event === 'turn_end') detail = `${t.ok ? 'ok' : 'failed'} · ${fmtTime(Number(t.duration)||0)} · ${fmtK(t.tokens)} tok`;
      else if (t.event === 'turn_start') detail = 'started';
      else detail = JSON.stringify(t).slice(0,100);
      html += `<tr><td class="score">${esc(ago(t.ts))}</td><td>${esc(t.event || '?')}</td>` +
        `<td>${esc(t.agent || '-')}</td><td>${esc(String(t.round ?? '-'))}</td>` +
        `<td>${esc(detail)}</td></tr>`;
    });
    html += '</table>';
  }

  html += '<div class="section-title">heartbeat</div>';
  const hb = data.heartbeat || {};
  if (!hb.epoch) html += '<div class="empty">no heartbeat yet</div>';
  else {
    html += `<table><tr><th>round</th><th>phase</th><th>agent</th><th>when</th></tr>` +
      `<tr><td>${esc(String(hb.round ?? '-'))}</td><td>${esc(hb.phase || '-')}</td>` +
      `<td>${esc(hb.agent || '-')}</td><td>${ago(hb.epoch)}</td></tr></table>`;
  }

  document.getElementById('content').innerHTML = html;
  renderWarnings(data);
  renderFeed(data);
  renderTimeline();
  renderPause(data);
}

function renderFeed(data) {
  const feed = [];
  (data.recent_actions || []).forEach(a => feed.push({t:a.timestamp, who:'action',
    text:'$ '+a.command+(a.result?`  →  ${a.result}`:''), kind:'action'}));
  (data.messages || []).forEach(m => feed.push({t:m.timestamp, who:`${m.from_agent} → ${m.to_agent}`,
    text:`[${m.msg_type}] ${m.text}`, kind:'msg'}));
  feed.sort((x,y)=>y.t-x.t);
  const el = document.getElementById('feed');
  if (!feed.length) { el.innerHTML = '<div class="empty">no activity yet</div>'; return; }
  el.innerHTML = feed.slice(0,20).map(f =>
    `<div class="feedrow"><span class="ago">${ago(f.t)}</span>` +
    `<span class="${f.kind==='msg'?'msg-type-handoff':'msg-type-info'}">${esc(f.who)}</span>` +
    `<span>${esc(f.text.slice(0,240))}</span></div>`).join('');
}

/* ---- timeline ---- */
function renderTimeline() {
  const el = document.getElementById('timeline');
  if (!el || !lastState) return;
  const filt = document.getElementById('timeline-filter').value;
  const rows = (lastState.timeline || []).filter(e => !filt || e.kind === filt);
  document.getElementById('timeline-count').textContent = `${rows.length} event(s)`;
  if (!rows.length) { el.innerHTML = '<div class="empty">no events yet</div>'; return; }
  el.innerHTML = '<div id="feed">' + rows.map(e =>
    `<div class="feedrow"><span class="ago">${ago(e.t)}</span>` +
    `<span class="msg-type-${e.kind==='msg'?'handoff':e.kind==='milestone'?'finding':'info'}">${esc(e.kind)} · ${esc(e.who)}</span>` +
    `<span>${esc(e.text.slice(0,300))}</span></div>`).join('') + '</div>';
}

/* ---- control ---- */
function fillSteerSelects() {
  const toS = document.getElementById('steer-to');
  if (toS.options.length === 0) {
    STEER_AGENTS.forEach(a => toS.appendChild(new Option(a,a)));
    const tc = document.getElementById('steer-type-choice');
    STEER_TYPES.forEach(x => tc.appendChild(new Option(x,x)));
  }
}
async function sendSteer() {
  const st = document.getElementById('steer-status');
  const to = document.getElementById('steer-to').value;
  const typ = document.getElementById('steer-type-choice').value;
  const txt = document.getElementById('steer-text').value.trim();
  if (!current || !txt) { st.textContent='workspace + message text required'; st.className='err'; return; }
  st.textContent='sending...'; st.className='';
  try {
    const r = await fetch('/api/steer', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({workspace: current, to, type: typ, text: txt})});
    const j = await r.json();
    if (j.ok) { st.textContent=`posted to ${to} (${j.msgid}) — picked up next turn`; st.className='ok';
      document.getElementById('steer-text').value=''; }
    else { st.textContent='failed: '+(j.error||r.status); st.className='err'; }
  } catch(e) { st.textContent='failed: '+e; st.className='err'; }
}
async function claimLead() {
  const st = document.getElementById('claim-status');
  const id = document.getElementById('claim-lead-id').value.trim();
  if (!current || !id) { st.textContent='workspace + lead id required'; st.className='err'; return; }
  try {
    const r = await fetch('/api/leads/claim', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({workspace: current, id})});
    const j = await r.json();
    if (j.ok) { st.textContent=`claimed ${id} (operator) — agents will skip it`; st.className='ok'; }
    else { st.textContent='failed: '+(j.error||r.status); st.className='err'; }
  } catch(e) { st.textContent='failed: '+e; st.className='err'; }
}
function renderPause(data) {
  const btn = document.getElementById('pause-btn');
  const st = document.getElementById('pause-status');
  if (!btn) return;
  if (data && data.paused) {
    btn.textContent = 'clear pause request'; btn.className='btn good';
    st.textContent = 'pause requested — orchestrator stops after the current turn'; st.className='pause-on';
  } else {
    btn.textContent = 'pause after current turn'; btn.className='btn warn';
    st.textContent = 'runs to the end of the current turn, flushes state, then exits resumable';
    st.className='';
  }
}
async function togglePause() {
  if (!current) return;
  const value = !(lastState && lastState.paused);
  try {
    const r = await fetch('/api/pause', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({workspace: current, value})});
    const j = await r.json();
    if (j.ok) { if (lastState) lastState.paused = value; renderPause(lastState); }
  } catch(e) {}
}
function refreshControl() {
  fillSteerSelects();
  if (!lastState) return;
  const box = document.getElementById('replies');
  const msgs = (lastState.messages||[]).slice().sort((a,b)=>b.timestamp-a.timestamp);
  if (!msgs.length) { box.innerHTML='<div class="empty">no mailbox traffic yet</div>'; return; }
  box.innerHTML = msgs.map(m =>
    `<div class="feedrow"><span class="ago">${ago(m.timestamp)}</span>` +
    `<span>${esc(m.from_agent+' → '+m.to_agent)}</span>` +
    `<span class="msg-type-${m.msg_type}">${esc(m.text.slice(0,600))}</span></div>`).join('');
}

/* ---- learn ---- */
let learnCache = null;
async function loadCandidates() {
  if (!current) return;
  const el = document.getElementById('candidates');
  try {
    const r = await fetch('/api/learn-candidates?workspace='+enc(current));
    const j = await r.json();
    const cs = j.candidates || [];
    if (!cs.length) { el.innerHTML='<div class="empty">no candidates yet — run a session, then `bb learn`</div>'; return; }
    el.innerHTML = '<table><tr><th>id</th><th>kind</th><th>category</th><th>name</th><th>approved</th><th>action</th></tr>' +
      cs.map(c => `<tr><td>${esc(c.id)}</td><td>${esc(c.kind)}</td><td>${esc(c.category)}</td>` +
        `<td>${esc(c.name)}</td><td>${c.approved?'yes':''}${c.committed?' (committed)':''}</td>` +
        `<td><button class="btn ${c.approved?'warn':'good'}" onclick="approveCandidate('${esc(c.id)}', ${c.approved?'false':'true'})">` +
        `${c.approved?'unapprove':'approve'}</button></td></tr>`).join('') + '</table>';
  } catch(e) { el.innerHTML='<div class="empty">candidates unreadable</div>'; }
}
async function approveCandidate(id, value) {
  if (!current) return;
  await fetch('/api/learn/approve', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({workspace: current, id, value})});
  loadCandidates();
}
async function loadLearnIndex() {
  if (learnCache) return renderLearn(learnCache);
  try { const r = await fetch('/api/learn'); learnCache = await r.json(); renderLearn(learnCache); }
  catch(e) {}
}
function renderLearn(docs) {
  if (!docs || !docs.length) { document.getElementById('learn-list').innerHTML='<div class="empty">no writeups or skills yet</div>'; return; }
  const kinds = {};
  docs.forEach(d => (kinds[d.kind]=kinds[d.kind]||[]).push(d));
  const order = ["run writeup","engagement report","learned skill"];
  const el = document.getElementById('learn-list'); el.innerHTML='';
  order.forEach(kind => {
    if (!kinds[kind]) return;
    const h = document.createElement('div');
    h.className='section-title'; h.style.margin='10px 6px 2px'; h.textContent=kind+'s';
    el.appendChild(h);
    kinds[kind].forEach(d => {
      const it = document.createElement('div');
      it.className='learnitem'; it.dataset.path=d.path;
      it.innerHTML = `<span class="kind">${esc(d.kind)}</span>${esc(d.title)}`;
      it.onclick = () => { document.querySelectorAll('.learnitem').forEach(x=>x.classList.remove('active'));
        it.classList.add('active'); openDoc(d.path); };
      el.appendChild(it);
    });
  });
}
async function openDoc(path) {
  const box = document.getElementById('learn-doc');
  box.innerHTML='<div class="empty">loading...</div>';
  try {
    const r = await fetch('/api/doc?src='+enc(path)); const j = await r.json();
    if (j.error) { box.innerHTML='<div class="empty">'+esc(j.error)+'</div>'; return; }
    box.dataset.raw = j.raw; box.dataset.rawShown='';
    box.innerHTML = '<a href="#" onclick="viewRaw();return false;" style="font-size:10px;color:#8b949e;float:right;">view raw</a>' + mdToHtml(j.raw);
  } catch(e) { box.innerHTML='<div class="empty">load failed</div>'; }
}
function viewRaw() {
  const box = document.getElementById('learn-doc');
  if (box.dataset.rawShown) { box.dataset.rawShown=''; box.innerHTML=mdToHtml(box.dataset.raw); return; }
  box.dataset.rawShown='1'; box.innerHTML='<pre><code>'+esc(box.dataset.raw)+'</code></pre>';
}
function mdToHtml(md) {
  let html=''; let inCode=false, codeBuf=[];
  const esc_ = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  md.split('\n').forEach(line => {
    if (/^```/.test(line.trim())) {
      if (inCode) { html += '<pre><code>'+esc_(codeBuf.join('\n'))+'</code></pre>'; codeBuf=[]; }
      inCode=!inCode; return;
    }
    if (inCode) { codeBuf.push(line); return; }
    let t = esc_(line);
    const h = /^(#{1,3})\s+(.*)/.exec(line);
    if (h) { const n=h[1].length; html += `<h${4-n}>${t.slice(n+1)}</h${4-n}>`; return; }
    if (/^\s*[-*]\s+/.test(line)) { html += '<li>'+inline(t.replace(/^\s*[-*]\s+/,''))+'</li>'; return; }
    if (/^(-{3,}|_{3,})$/.test(line.trim())) { html += '<hr>'; return; }
    if (t.trim()==='') { html += '<br>'; return; }
    html += inline(t)+'<br>';
  });
  if (inCode) html += '<pre><code>'+esc_(codeBuf.join('\n'))+'</code></pre>';
  function inline(s) {
    return s.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>')
      .replace(/`([^`]+)`/g,'<code>$1</code>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  }
  return html;
}

/* ---- live loop (long-poll) ---- */
async function loadTargets() {
  try {
    const res = await fetch('/api/targets'); const targets = await res.json();
    const el = document.getElementById('targets'); el.innerHTML='';
    if (!targets.length) {
      document.getElementById('content').innerHTML='<div class="empty">no state.json found under labs/ or programs/ yet</div>';
      return;
    }
    if (!current || !targets.includes(current)) { current = targets[0]; stateVersion=''; }
    targets.forEach(t => {
      const b = document.createElement('button');
      b.className='target-btn'+(t===current?' active':'');
      b.textContent=t; b.onclick=()=>{ current=t; stateVersion=''; pollGen++; loadTargets(); pollState(); };
      el.appendChild(b);
    });
  } catch(e) {}
}
async function pollState() {
  const gen = ++pollGen;
  while (gen === pollGen) {
    if (!current) { await sleep(500); continue; }
    const ws = current;
    try {
      const res = await fetch('/api/state?workspace='+enc(ws)+'&since='+enc(stateVersion));
      const j = await res.json();
      if (gen !== pollGen || ws !== current) continue;
      if (j.error) {
        document.getElementById('content').innerHTML = '<div class="empty">state unreadable: '+esc(j.error)+'</div>';
        await sleep(2000); continue;
      }
      if (!j.unchanged) { stateVersion = j.version; renderMonitor(j); }
    } catch(e) { await sleep(1500); }
    await sleep(150);
  }
}
loadTargets();
setInterval(loadTargets, 5000);
pollState();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    root: Path = ROOT

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _workspaces(self) -> dict[str, Path]:
        root = self.server.app_root
        return {config.rel(w, root): w for w in discover_workspaces(root)}

    def do_GET(self):
        parsed = urlparse(self.path)
        root = self.server.app_root
        if parsed.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/targets":
            self._json(list(self._workspaces().keys()))
            return
        if parsed.path == "/api/state":
            qs = parse_qs(parsed.query)
            requested = qs.get("workspace", [""])[0]
            since = qs.get("since", [""])[0]
            valid = self._workspaces()
            if requested not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            ws = valid[requested]
            deadline = time.time() + POLL_SECONDS
            while True:
                version = _version(root, ws)
                if version != since or time.time() >= deadline:
                    break
                time.sleep(0.4)
            if version != since:
                try:
                    data = workspace_summary(ws, root)
                except Exception as e:
                    self._json({"error": f"state unreadable: {e!r}"}, status=500)
                    return
                self._json(data)
            else:
                self._json({"version": version, "unchanged": True})
            return
        if parsed.path == "/api/learn":
            self._json(learn_files(root))
            return
        if parsed.path == "/api/learn-candidates":
            qs = parse_qs(parsed.query)
            valid = self._workspaces()
            requested = qs.get("workspace", [""])[0]
            if requested not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            self._json(learn.load(valid[requested]))
            return
        if parsed.path == "/api/doc":
            qs = parse_qs(parsed.query)
            raw = doc_content(root, qs.get("src", [""])[0])
            if raw is None:
                self._json({"error": "not found or not an .md inside the scan root"}, status=404)
                return
            self._json({"raw": raw.decode("utf-8", "replace")})
            return
        self.send_response(404)
        self.end_headers()

    def _body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > 16384:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            return None

    def do_POST(self):
        parsed = urlparse(self.path)
        root = self.server.app_root
        valid = self._workspaces()
        body = self._body()
        if body is None:
            self._json({"error": "bad or oversized JSON body"}, status=400)
            return

        if parsed.path == "/api/steer":
            workspace = body.get("workspace", "")
            to = body.get("to", "")
            text = str(body.get("text", "")).strip()
            msg_type = body.get("type", "request")
            if workspace not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            if to not in STEER_AGENTS:
                self._json({"error": "unknown target agent"}, status=400)
                return
            if msg_type not in STEER_TYPES:
                self._json({"error": "type must be one of " + ",".join(sorted(STEER_TYPES))}, status=400)
                return
            if not text or len(text) > 6000:
                self._json({"error": "empty or oversized message (max 6000 chars)"}, status=400)
                return
            cmd = [sys.executable, str(root / "lib" / "state.py"), str(valid[workspace]),
                   "post-msg", "--from", "user", "--to", to,
                   "--type", msg_type, "--text", text]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            except subprocess.TimeoutExpired:
                self._json({"error": "state CLI timed out"}, status=500)
                return
            if r.returncode != 0:
                self._json({"error": (r.stderr or "CLI failed").strip()[-300:]}, status=500)
                return
            out = r.stdout.strip().split()
            self._json({"ok": True, "msgid": out[1] if len(out) > 1 else "?"})
            return

        if parsed.path == "/api/leads/claim":
            # §3.6: operator claims a lead by hand so specialists never
            # double-work something a human already picked up
            workspace = body.get("workspace", "")
            if workspace not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            hit = leads.claim(valid[workspace], str(body.get("id", "")),
                              note=str(body.get("note", "")) or None,
                              claimant="operator")
            if not hit:
                self._json({"error": "lead not found"}, status=404)
                return
            self._json({"ok": True, "lead": hit})
            return

        if parsed.path == "/api/pause":
            workspace = body.get("workspace", "")
            if workspace not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            try:
                statex.request_pause(valid[workspace], bool(body.get("value", True)))
            except Exception as e:
                self._json({"error": f"could not write pause sentinel: {e!r}"}, status=500)
                return
            self._json({"ok": True, "paused": bool(body.get("value", True))})
            return

        if parsed.path == "/api/learn/approve":
            workspace = body.get("workspace", "")
            if workspace not in valid:
                self._json({"error": "unknown workspace"}, status=404)
                return
            hit = learn.approve(valid[workspace], str(body.get("id", "")),
                                bool(body.get("value", True)))
            if not hit:
                self._json({"error": "candidate not found"}, status=404)
                return
            self._json({"ok": True, "candidate": hit})
            return

        self.send_response(404)
        self.end_headers()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=".", help="directory to scan (default: cwd)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()

    root = Path(args.root).resolve()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.app_root = root  # type: ignore[attr-defined]
    print(f"scanning {root} for labs/*/machines/*/state.json and programs/*/state.json")
    print(f"dashboard: http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
