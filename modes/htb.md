# HTB LAB MODE

## Scope
- Only Hack The Box: machines, challenges, Academy labs, Sherlocks, Pro Labs,
  or a local training box you own.
- Target is pre-authorized for the duration of the lab/VPN session. No
  external scope check needed — skip straight to recon.

## State
Every run loads/saves `labs/HTB/machines/<name>/state.json`. Everything
below that reads as `state.add_hypothesis(...)` etc. is the Python API
(`lib/state.py`); as a running agent, call the same thing as a shell
command instead — `python3 lib/state.py <workspace> add-hyp --id ...`, see
`lib/state.py`'s own `--help` for the full CLI, or `agents/*.md` for
worked examples of each call. Before executing any command, check
`already-tried`. If it's been run, don't re-run it blind — either skip it
or explicitly justify why conditions changed (new creds, new port, etc.)
in the hypothesis that calls for it.

**Single-process vs multi-agent**: this file is the shared policy for
both. Running solo, you (the orchestrator) do every step yourself. Running
as part of a multi-agent team (`scripts/multi_agent_run.py` +
`agents/{recon,web,ad,privesc}-agent.md`), each specialist does steps 2-7
within its own lane and hands off via the mailbox (`post-msg`/`inbox`)
instead of doing every step itself.

## Workflow

1. **Understand**
   - Parse the machine/challenge description, target IP, hostname, OS.
   - Load prior state if this lab has a partial run already.
   - Bootstrap the workspace so the driver/dashboard can see the run from the
     start: `python3 lib/state.py <workspace> set-target --target <ip> --mode htb`.

2. **Recon**
   - Minimum useful enumeration first. Read full results before deciding the
     next scan — don't fire a second tool before the first one's output has
     actually been reasoned over.
   - No blind full-port / all-scripts scans as a first move.

3. **Hypothesis generation**
   For each candidate attack path, call `state.add_hypothesis(id, statement,
   evidence, confidence, cost, test)`. Before running a new tool, call
   `state.next_hypothesis()` and work that one — don't just run whatever
   seems obvious in the moment. This is what keeps the agent from thrashing.

4. **Exploitation**
   - Take the highest confidence/cost hypothesis first.
   - Record why it should work (`evidence`) before attempting it.
   - Keep observation separate from assumption in the hypothesis `result`.

5. **Pivoting / privesc**
   - Enumerate perms, services, creds, config, AD relationships, sudo rights,
     scheduled tasks, tokens.
   - For AD boxes, build the attack graph as hypotheses, not as one giant
     unstructured BloodHound dump re-read every turn.

6. **Failure memory**
   - Any technique that's confirmed dead: `state.mark_failed(description,
     reason)`. Check `state.is_known_failed()` before re-attempting
     something that looks similar.

7. **Objective verification**
   - Confirm the actual flag/objective, not just "got a shell."
   - `state.mark_milestone("user")` / `state.mark_milestone("root")` /
     `state.mark_milestone("flag")` as you hit them — this is what feeds the
     benchmark AND what stops the multi-agent driver (`flag` OR `root`).
     A run that owns the box but never marks a milestone loops to
     `--max-rounds` instead of ending cleanly.
   - Milestones are keep-first: a re-mark is a no-op, so a slip can't reset
     the clock. Noticed one late? Backfill the true time with `--at <epoch>`
     (e.g. `--at $(stat -c %Y <loot-file>)`).

8. **Writeup** (write to `labs/HTB/machines/<name>/writeup.md` — the
   dashboard's Learn tab also indexes `postmortem.md`/`WRITEUP.md`)
   - ROOT CAUSE
   - ATTACK CHAIN
   - MISCONFIGURATION
   - DETECTION OPPORTUNITIES
   - MITIGATION
   - REUSABLE TECHNIQUE

9. **Skill creation**
   - Any reusable technique becomes a new file under `skills/<category>/`,
     short and procedural, so the bug-bounty-mode agent can pull it in later.
   - Shape: name + one-line trigger ("when to use"), then numbered procedure,
     then pitfalls. No flag values.
   - Example: `skills/web/grommunio-appliance-exploitation.md`.
   - Verify it's discoverable: `python3 scripts/skills_lookup.py <keyword>`
     (flat `skills/` files are indexed automatically; the dashboard Learn
     tab picks them up too).

10. **Close-out** (the moment root/flag lands — don't defer to "later"; the
    Autopilot run stalled at user.txt because nothing recorded the end, so
    the driver never stopped and no run row/benchmark was ever written)
    - Mark `root`/`flag` immediately (step 7), backfilling with `--at` if
      you're catching up after the fact.
    - Write `writeup.md` (step 8) and extract skills (step 9).
    - Append a row to `INDEX.md` §4 run history (outcome, one-line chain,
      top lesson).
    - Snapshot the auto-derived benchmark:
      `python3 lib/state.py <workspace> benchmark > benchmark/runs/<machine>-<date>.json`.
    - Multi-agent run still going? It self-stops on the first `flag`/`root`
      milestone; otherwise stop it and let it print the final summary.

## Before every tool call, run the critic gate (see `agents/critic-agent.md`)
1. What are we trying to prove?
2. What evidence supports this?
3. Did we already test it? (`state.already_tried`)
4. Is there a cheaper test?
5. What result would confirm/refute it?
6. What happens next for each possible result?
