# HANDOFF BRIEFING — Agentic Bug Bounty on OpenCode (Free Models)

**Context for the receiving (stronger) model:** The operator has a working-but-improvised agentic
pentest/bug-bounty workspace at `/home/kali/bugbounty/`, driven by **OpenCode CLI** (v1.18.x) with
**free models** (e.g. `dahl/zai-org/GLM-5.3-Flash`, `deepseek-v4.1-flash-free`). Your job after
reading this: produce a **full build plan for a single, customized, opencode-native bug-bounty CLI**
that packages/wraps/improves everything below. Everything described is verified on disk.

---

## 1. Workspace inventory (what exists today)

### 1.1 The core engine (homegrown, the crown jewel)
- `lib/state.py` (549 lines) — persistent state per target workspace (`state.json`):
  - **Hypothesis engine**: statement, evidence, confidence 0–1, cost (effort 1=cheap), test plan,
    status (open/confirmed/refuted/rejected). Ranking: `score = confidence / max(cost, 0.1)` —
    "cheap, promising tests first". `next-hyp` is deliberately dumb/deterministic so it's cheap
    to call every turn instead of re-reasoning in-context.
  - **Action dedup**: sha256 of whitespace-normalized command text; `already-tried` check.
  - **Failed-path memory**: `mark-failed` / `is-known-failed` (case-insensitive) — no silent retries.
  - **Milestones**: keep-first semantics (re-marking is a no-op; benchmark clock can't be reset),
    standard names `user`, `root`, `flag`; `--at <epoch>` for backfilling late-noticed events.
  - **Agent mailbox**: `post-msg` / `inbox --for` / `mark-read`. Durable blackboard, not live channel.
  - **Hardening for free models**: flock on `<workspace>/.state.lock` for every mutation, atomic
    `.tmp`+`os.replace` saves, tolerant coercion of schema drift, unknown keys preserved verbatim.
  - Design rationale (quoted in code): "a free model shelling out to a documented CLI command is far
    more reliable than it writing correct inline Python every turn."
- `agents/` (7 role prompts): orchestrator, critic-agent (pre-tool-call gate: 8 questions →
  `ALLOW/BLOCK`, incl. scope gate Q7 and skill-library check Q8), recon-agent, web-agent, ad-agent,
  privesc-agent, linux-privesc-agent. Each specialist: drain inbox → dedup check → critic gate →
  lane work (turning output into hypotheses) → record via state.py CLI → mailbox handoff,
  then "take exactly one turn" and stop.
- `modes/htb.md` (112 lines, 10-step workflow) and `modes/bugbounty.md` (41 lines). Bounty mode's
  headline: **scope is a hard gate, not a suggestion** — must load `programs/<program>.json` scope
  first; anything not listed = stop and flag. Validation = "minimum request volume to prove impact".
  Both modes end with: writeup → extract reusable technique into `skills/<category>/<name>.md`
  (learning loop) → close-out.
- `scripts/`:
  - `multi_agent_run.py` (262 lines) — the round-robin driver. Inlines `agents/<role>.md` +
    mode file into each specialist's prompt, spawns separate `opencode run -m <model> -s <session>`
    subprocesses, harvests sessionID from `--format json` stdout for session continuity, stops the
    whole run when a `root` or `flag` milestone exists. Parallel-safe (flock-serialized state).
  - `dashboard.py` (662 lines) — stdlib-only live HTML monitor at 127.0.0.1:8765; Monitor /
    Control (operator steering injects mailbox messages) / Learn tabs; loopback-only binding.
  - `skills_lookup.py` (210 lines) — deterministic keyword skill retrieval (token overlap +
    pentest synonym table + substring fuzz; no embeddings, near-free to call every time).
    Indexed roots declared in `lib/skill_roots.json`.
  - `smoke_test.py` (158 lines) — offline end-to-end test of state.py. "Run FIRST, before burning
    any model calls."
  - `capture-command.py` — argv-exec evidence runner (argv/cwd/timestamps/rc/stdout/stderr to
    timestamped run dirs).
  - `init-program.py` — copies `programs/_template/` → `programs/<slug>/` (dupe/traversal checks).
  - `htb_target_provider.py` — pyhtb HTB automation; on spawn writes `programs/htb/<name>.json`
    scope file so HTB targets satisfy bounty-mode's scope gate.
- `benchmark/` — free-model comparison harness: `template.json` (auto block: unique_actions,
  hypotheses confirmed/refuted, dead_ends, time_to_first_path/user/root/flag; judged block 1–10:
  recon_quality, hypothesis_quality, tool_selection, web/ad reasoning, false_assumptions, hints…),
  `compare.py`. 5 saved runs. **Best**: Connected — 23 actions, 1 dead end, root in 567 s.
  **Pathological**: Autopilot — 196 actions, 26 dead ends, ~29.5 h (stalled because no stop
  milestone was ever marked; this taught the "stop on root OR flag" rule).
- `findings/INDEX.md` — master ledger: run history, learned skills, cleanup TODOs, known issues.

### 1.2 Skill libraries (four packaged roots + one flat learned tree)
- `bug-bounty-skills/` — **19 vuln-class skills** (ssrf, idor-bola, xxe, race-conditions,
  auth-bypass, sqli, xss, request-smuggling, cache-poisoning, deserialization, oauth-oidc, jwt,
  graphql, file-upload, path-traversal, prototype-pollution, ssti, cors, business-logic). All share
  a 12-section template (scope gate → core internals → lab workflow → real-world methodology →
  escalation → elite thinking → hexstrike-ai role → OpenCode tasks → lab topology → evidence
  checklist → stop conditions). Plus `AGENT_SYSTEM_PROMPT.md` ("Never assume scope", "hypothesis-
  driven over payload spraying", "do not claim a vuln without manual repro evidence"),
  `engagement-checklist.md` (10 pre-engagement safety items incl. request-rate ceiling), `scope.env.example`.
- `skills/` — **856 dirs, 51 MB**, merged from 4+ sources: briiirussell/cybersecurity-skills
  (base repo w/ adapters), mahipal batch pack (771 dirs, Apache-2.0, uniform SKILL.md+LICENSE+assets),
  mukul975+misc (53), **19 hand-written custom skills** (bug-bounty, bb-methodology, web2-recon,
  web2-vuln-classes, web3-audit, graphql-audit, llm-redteam, meme-coin-audit, argus, …), and loose
  learned-technique dirs `ad/`, `postexploitation/`, `privesc/`, `recon/`, `web/` (flat `.md`, e.g.
  `grommunio-appliance-exploitation.md` "Proven on HTB Autopilot", `ntlm-relay-responder-broker.md`,
  `ad-ksu-name-collision-local-root.md`).
- `agentic-bug-hunter/skills/` — ~21 dirs (argus, bb-methodology, web2-recon, web2-vuln-classes,
  web3-audit, security-arsenal, report-writing, triage-validation, credential-attack, …).
- Known issue: heavy near-duplicate clusters across sources (Volatility ×5, Trivy scanning ×4…);
  no exact content duplicates. Skill count claims in docs drift (9 vs 13 vs 21).

### 1.3 `agentic-bug-hunter/` (AwareXone v6.0.1, upstream toolkit — read for ideas to port)
Three products in one repo: Claude Code plugin, OpenCode framework, **standalone Python CLI**
(`bughunter/`, ~28k lines):
- `brain.py` (2877 lines): LLM provider layer w/ **MODEL_PRIORITY free-first ordering**
  (ollama, groq free tier llama-3.3-70b, deepseek cheap; paid fallbacks), pentester persona,
  **confirmation-gated `run_command`** (operator types exact command; env allowlist
  PATH/HOME/LANG/TERM only; output capped 8KB; rejects dangerous defaults).
- `agent.py`: LangGraph ReAct + native-Ollama fallback; memory layers (working/ findings/
  observation buffer/session file crash-resilient); `_CANDIDATE_SKILL` maps scanner keywords →
  verifying skill so **discovery never confirms its own bug**.
- `tools/`: `lead_board.py` (JSONL lead ingestion/claim/touch — "hunter focuses on one lead; the
  board remembers the rest"), `validate.py` (**4 gates + 7-Question Gate**: is_real / in_scope /
  exploitable / not_dup; CVSS; report skeleton; H1 duplicate check), `swarm.py` (XBOW-style
  coordinator + ThreadPoolExecutor workers claiming leads, isolated verdicts verified/killed/parked),
  `scope_checker.py`, `zero_day_fuzzer.py`, `token_scanner.py`, WAF bypass encoders (incl.
  invisible-unicode U+2062/U+2064 prompt-injection), `memory/` (JSONL schemas w/ validation,
  evidence hashing + replay, **RateLimiter, CircuitBreaker, SafeMethodPolicy, AutopilotGuard**,
  10MB rotation + redaction), MCP server (20 `bughunter_*` tools `mcp serve`).
- 42 slash-commands, 9–11 agents, `rules/hunting.md` (17 critical rules incl. "never hunt
  theoretical bugs"), `engine.py` (setup/recon/hunt/validate/report/status/models with provider
  autodetect — works with zero AI), install.sh supporting 7 harnesses (claude/opencode/codex/…).
- **Known gaps in upstream**: docs-vs-code drift (counts wrong everywhere); Stop-hook memory-GC is
  Claude-specific (opencode has no hooks CLI used here); commands need YAML-frontmatter translation
  to opencode format; thread-based swarm (fine for 1 box); a "pipedrag" tool the operator expected
  does not exist in this repo.

### 1.4 Working data (real runs — proof the system works)
- `labs/HTB/machines/` — 13 machine workspaces (Autopilot, Connected, DutyBound, DarkZeroReturns,
  Garfield, enigma, Paperwork, cap, Checkpoint, Bedside, MakeSense, Nimbus). Each: state.json +
  agent_logs/ + scans + exploits + loot (+ writeup/postmortem).
- `programs/` — `_template/` (scope.md, endpoints.csv, accounts.md, hypotheses.md,
  reports/finding-template.md, evidence/, requests/), `htb/*.json` (auto-generated scoped targets),
  `infomaniak/` — a fully worked **live YesWeHack program** (51-scope scope.md with exclusions and
  required UA header, H-001…H-007 hypothesis ledger with mandatory controls/negative results,
  evidence A/B comparison pairs).
- `findings/` — Indexed ledger, 8 HTB writeups, kill-chain artifacts, negative-result files
  (first-class convention), credential loot, tool dumps named `UTC_tool.{txt,json,zip}`.
- `scafoold/` — residual loot of ADCS-lab runs (administrator.pfx, ccache tickets, Certipy dumps
  proving ESC7/ESC8, revmail payload); plus original workspace README and a 4-root `opencode.json`.
- `setup/` — verification history: OpenCode 1.18.34 + `opencode.json` skills.paths; tool versions
  (subfinder v2.16.0, httpx v1.12.0 **Go binary at /home/kali/go/bin/httpx** — classic python-
  httpx shadowing gotcha; katana 1.7.0; ffuf 2.1.0; nucleI v3.11.1; Burp 2026.8-0kali1);
  HexStrike MCP backend as systemd user unit on 127.0.0.1:8888 v6.0.1 (lazily-configured client);
  capture-run evidence dirs. Burp GUI/proxy verification = still incomplete.
- Encore issues from INDEX: writeup-name convention drift (writeup.md / WRITEUP.md / postmortem.md);
  cleanup TODOs (drop root-owned `Burp-Suite/`, keep `Burpsuite-Professional/`, rotate loot);
  empty 0-byte `sessionresume_*` markers.

### 1.5 MCP / tooling environment
- HexStrike-AI MCP (127.0.0.1:8888) exposes nmap/httpx/nuclei/feroxbuster/sqlmap/nuclei/… tooling.
- Burp (Burp MCP connector referenced in agents/web-agent.md; GUI proxy never verified).
- Local Kali toolchain installed & version-verified (see above).
- Models observed in logs: `dahl/zai-org/GLM-5.3-Flash` (primary in runs),
  `deepseek-v4.1-flash-free`. agent_logs show transient `APIError: Cannot connect to API`
  (free endpoints are flaky → design must tolerate retry/empty turns).

---

## 2. Proven architecture flow (current system)

```
htb_target_provider start <machine>          # or init-program.py for live bounty
  → writes programs/*/scope json
multi_agent_run.py --workspace labs/HTB/machines/X --mode htb --model dahl/zai-org/GLM-5.3-Flash
  each round:
    for each of 5 specialists (parallel ok):
      prompt = agents/<role>.md + modes/<mode>.md + "take exactly one turn"
      opencode run -m <model> -s <session>        # session continuity
        ├─ scripts/skills_lookup.py "<kw>"        # MANDATORY before hand-rolling (critic Q8)
        ├─ lib/state.py next-hyp / already-tried / is-known-failed
        ├─ critic-agent gate: ALLOW/BLOCK (Q7 scope, Q8 skill-library)
        ├─ act (hexstrike MCP / burp / shell)
        ├─ lib/state.py record-action / update-hyp / mark-failed / mark-milestone
        └─ lib/state.py post-msg / inbox          # handoffs to other specialists
    stop when milestones has 'root' OR 'flag'
  → benchmark auto summary           → operator fills judged block
  → writeup.md                       → learned skill extracted to skills/<category>/<name>.md
```

**Five design principles repeated across every layer** (the things that make this work):
1. Deterministic CLI bookkeeping over model reasoning — the engine "calls no model"; opencode is
   assumed dumb but persistent; state.py is the shared brain.
2. Hypothesis-driven, dedup-gated, cheap-test-first tool use (tool spam + circular reasoning is the
   "biggest failure mode in agentic pentesting" — critic-agent exists for that).
3. Scope = absolute hard gate in bounty mode (skill lists are transferable, authorization is not).
4. Milestones marked the moment they're true (benchmark honesty); keep-first semantics.
5. Learning loop: every run distills reusable techniques into flat skills the next run retrieves.
6. (Implied) Evidence/proof discipline: capture-command, negative results recorded, hypothesis
   must have control/paired evidence to survive conflict.

---

## 3. What the operator wants from you

**Goal**: a single, polished, **customized opencode-native bug-bounty CLI** (one entrypoint wrapping
the above), designed around **free models** (dahl/zai-org/GLM-5.3-Flash, deepseek-free, groq free
tier via OpenAI-compatible endpoints — see brain.py's MODEL_PRIORITY for the provider-swap pattern),
fitted to the operator's real setup (Kali, HexStrike MCP, Burp, HTB + live programs).

### Constraints the plan must respect
- LLMs are weak/unreliable → all decision-critical flow stays deterministic (state.py CLIs,
  skills_lookup, validate gates); the model only proposes/test/executes one turn at a time.
- Free endpoints flake (APIError storms in logs) → retry/backoff, resumable sessions, per-turn logs
  that survive crashes, run IDs that never lose a sessionID.
- Operator steers interactively (dashboard "Control" tab already exists) → CLI should have a mode
  pairing a driving daemon with a live console.
- Live bounty program (infomaniak) shows the end-state vocabulary: hypothesis ledger with
  mandatory controls, evidence-by-path (never paste secrets into state), negative results recorded.
- Scope gate must never be bypassable by any model output.

### Candidate blueprint directions (validated features from the scans — propose specifically)
1. **`bb` single binary** (Python, argparse-friendly like state.py) with subcommands chaining the
   existing pieces: `bb init <program>`, `bb scope-check`, `bb recon <target>`, `bb run
   [--mode htb|bounty] [--model …]`, `bb leads` (port lead_board), `bb validate <finding>`
   (port 4-gate validator), `bb report`, `bb skills <kw>` (skills_lookup), `bb benchmark,
   bb dashboard`, `bb steer <agent> <msg>`, `bb state ...` (thin exec of state.py).
2. **Free-model provider layer**: port brain.py's MODEL_PRIORITY pattern; config-first
   (models.yaml), no paid providers required; auto-switch on repeated APIError; per-turn
   transcripts with sessionID harvesting already proven in multi_agent_run.py.
3. **Critic as code, not just prompt**: the critic's Q7 (scope) and Q8 (skill-library) are cheaply
   mechanizable — implemented as pre-command hooks intercepting the agent's command pipeline.
4. **Learning loop already proven** → formalize: after each run, `bb learn` extracts technique →
   `skills/<category>/<name>.md`, re-indexable by skills_lookup in the same second.
5. **Memory/audit**: port the JSONL evidence hashing, rotation, redaction, rate-limiter/circuit-
   breaker/SafeMethodPolicy out of agentic-bug-hunter into lib/ so every hunting run inherits them.
6. **Opencode-native assets**: convert commands to `.opencode/commands/*.md` in opencode's YAML
   frontmatter format, register all skill roots in opencode.json (4 packaged roots + flat skills/),
   keep dashboard loopback-only.
7. Cleanup as part of the build: reconcile skill/command counts (manifest file), unify writeup
   naming (choose `writeup.md` or `postmortem.md`), drop root-owned Burp-Suite/, rotate loot,
   document the httpx Go-vs-Python gotcha in the CLI bootstrap doctor.

### Open questions the receiving model should answer
- Thread vs file-queue swarm (XBOW-style) inside one CLI process?
- Where does memory live: `~/.config/<cli>/memory/` workspace-side or in per-workspace state.json?
- Should critic-agent remain an LLM prompt for nuanced veto + deterministic code for the 2
  mechanizable gates, or full code-to-code?
- Clean-room rewrite vs package existing scripts into a CLI (recommendation: package-then-vet village)?
- Which subsets of agentic-bug-hunter's 42 commands/21 skills are worth translating to opencode
  format vs reinventing?

---

## 4. Files worth having the receiving model read directly (priority order)
1. `/home/kali/bugbounty/findings/INDEX.md` — run history + known issues ledger
2. `/home/kali/bugbounty/lib/state.py` — the deterministic brain (549 lines)
3. `/home/kali/bugbounty/scripts/multi_agent_run.py` — the driver
4. `/home/kali/bugbounty/agents/critic-agent.md` + `agents/orchestrator.md` — the protocol
5. `/home/kali/bugbounty/modes/htb.md` + `modes/bugbounty.md` — operating contracts
6. `/home/kali/bugbounty/benchmark/README.md` + `template.json` — scoring methodology
7. `/home/kali/bugbounty/programs/infomaniak/hypotheses.md` — live-program proof-of-work format
8. `/home/kali/bugbounty/programs/_template/reports/finding-template.md` — report skeleton
9. `/home/kali/bugbounty/agentic-bug-hunter/tools/validate.py` + `tools/lead_board.py` +
   `memory/schemas.py` — feature to port
10. `/home/kali/bugbounty/setup/verification.md` — exactly which tools exist & versions
