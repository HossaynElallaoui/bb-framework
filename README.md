# bb — Bug Bounty / HTB Automation Framework

A deterministic, round-robin multi-agent framework for bug bounty hunting and Hack The Box machines. Built on OpenCode with a critic-gate architecture.

## Features

- **Specialist agents**: recon, web, ad, privesc, linux-privesc, critic — each with focused prompts
- **Deterministic critic gate**: every action passes scope, already-tried, skill-library, and evidence-sufficiency checks
- **Round-robin scheduler**: parallel agents with adaptive AIMD rate limiting (persisted)
- **State management**: append-only action log, hypothesis tracking, mailbox for inter-agent handoffs
- **Web dashboard**: real-time agent status, token/cost tracking, long-polling updates
- **Skill library**: cached keyword lookup with 1800+ techniques
- **Benchmark priors**: hypothesis confidence auto-adjusted from historical runs

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
