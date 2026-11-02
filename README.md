# bb — Bug Bounty / HTB Automation Framework

A deterministic, round-robin multi-agent framework for bug bounty hunting and Hack The Box machines. Built on OpenCode with a critic-gate architecture.

## Features

- **Specialist agents**: recon, web, ad, privesc, linux-privesc, critic — each with focused prompts
- **Deterministic critic gate**: every action passes scope, already-tried, skill-library, and evidence-sufficiency checks
- **Round-robin scheduler**: parallel agents with adaptive AIMD rate limiting (persisted)
- **State management**: append-only action log, hypothesis tracking, mailbox for inter-agent handoffs
- **Web dashboard**: real-time agent status, token/cost tracking, long-polling updates
- **Skill library**: cached keyword lookup with 1800+ techniques
- **Similar-box retrieval**: solved-machine fingerprint index (weighted Jaccard over
  ports/services/products/OS) biases `next-hyp` toward categories that worked on the
  most similar past box
- **Composite bundles**: `bb composite list` — standard recon/enum chains in one turn
- **Asset diffing**: `bb assets scan` — passive subdomain enum + rate-limited probes,
  scope-gated, diffs against the last known asset set and can ingest new surface as leads
- **Synchronous validation**: `update-hyp --status confirmed` auto-creates a finding
  skeleton and runs the deterministic gates immediately (confirmed-but-unvalidated is visible)
- **Second-opinion pass**: every confirm gets a cheap, differently-prompted verifier turn on
  the existing evidence; a KICKBACK deterministically reverts the confirm (`--no-verify` to disable)
- **Multi-model router**: `models.yaml` maps task types (recon-parse / hypothesis-synthesis /
  exploit-attempt / report-draft) to ordered model lists with per-(model, task) health tracking;
  API-error storms escalate down the list into a `fallback:` tier (`bb router status`)
- **Speculative exploration**: `--speculate N` — parallel specialists work the top-N hypotheses
  concurrently instead of colliding on the top pick
- **Coverage map**: `bb coverage` — what has been enumerated vs not, derived from the action log;
  gaps steer recon and `next-hyp`
- **Payout weighting**: `programs/<slug>/payouts.json` orders equally-promising hypotheses by
  expected value (capped tiebreaker)
- **Dupecheck**: `bb dupecheck` — known-issues + operator dupcheck-hook signals before a
  report cycle is sunk into an already-filed bug
- **Learn redaction**: skills committed from live programs are scrubbed of hostnames/emails/tokens
- **Operator lead claims**: `bb leads claim --claimant operator` (and dashboard button) so
  specialists never double-work a lead a human picked up
- **Benchmark priors**: hypothesis confidence auto-adjusted from historical runs
- **Regression gate**: `bb benchmark pin` + `bb benchmark gate` fail any change that
  regresses actions/dead-ends/time-to-root beyond a tolerance band vs the pinned gold run

## Quick Start

```bash
# HTB machine
bb run --mode htb --machine Takeoff --target 10.129.96.117

# Resume later
bb run --resume labs/HTB/machines/Takeoff

# Bug bounty program
bb init acme-program
bb scope acme-program --add "*.acme.com"
bb run --mode bounty --program acme-program

# Dashboard
bb dashboard --port 8765
# Open http://localhost:8765
```

## Architecture

```
bb run (orchestrator)
    ├─ recon-agent      → port scan, service enum, tech detect
    ├─ web-agent        → app mapping, auth analysis, IDOR/JWT/SSTI
    ├─ ad-agent         → AD enumeration, kerberoasting, GPO abuse
    ├─ privesc-agent    → Linux/Windows local privilege escalation
    ├─ linux-privesc-agent → kernel exploits, sudo, capabilities, containers
    └─ critic-agent     → deterministic gate (scope, dedup, skills, evidence)
```

Each turn: drain inbox → skill check → critic gate → scope check → act → record → handoff.

## Project Structure

```
agents/           # Agent role prompts
lib/bb/           # Core framework (runner, state, session, gate, ratelimit, dashboard)
scripts/          # CLI entry points, smoke tests, dashboard server
modes/            # htb.md, bounty-auto.md, bugbounty.md
benchmark/        # Prior-adjusted hypothesis ranking
skills/           # Local skill library (1800+ techniques)
agentic-bug-hunter/  # Submodule: upstream agentic framework
```

## Requirements

- Python 3.11+
- OpenCode (`opencode` CLI)
- `rich`, `httpx`, `pyyaml`

## Submodules

```bash
git clone --recurse-submodules https://github.com/YOURUSER/bb-framework.git
# or after clone:
git submodule update --init --recursive
```

## License

Internal tooling — not for redistribution.
