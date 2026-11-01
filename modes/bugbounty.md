# BUG BOUNTY MODE

## Scope — hard gate, not a suggestion
- Load `programs/<program>.json` (or `programs/htb/<name>.json` for an HTB
  lab target staged through the HTB provider) before anything else.
- Every host/endpoint you touch must appear in that file's `scope.hosts`
  (or match its documented wildcard/subdomain rules). If a target isn't
  listed, stop and flag it — don't infer that it's probably in scope.
- Respect any out-of-scope list, rate limits, and testing-window
  restrictions the program file records.
- This mode never improvises scope. HTB-mode techniques transfer in
  (`skills/<category>/*.md`); HTB-mode's "assume authorized" assumption does
  not.

## State
Same mechanism as HTB mode: `programs/<program>/state.json` via
`lib/state.py`. Action dedup matters even more here — repeated requests
against a live target are noisier and slower than against a lab box, so
checking `state.already_tried()` before firing a request isn't optional.

## Workflow

1. **Load scope** — parse `programs/<program>.json`, confirm hosts, note
   any out-of-scope paths/subdomains explicitly.
2. **Recon** — within scope only. Passive/low-noise first.
3. **Hypothesis generation** — same `state.add_hypothesis(...)` /
   `state.next_hypothesis()` loop as HTB mode. Pull in relevant
   `skills/<category>/*.md` notes written from prior HTB runs before
   generating hypotheses from scratch.
4. **Validation** — minimum request volume to confirm a finding. No
   exploitation beyond what's needed to prove impact, per the program's
   rules of engagement.
5. **Failure memory** — `state.mark_failed(...)` same as HTB mode.
6. **Report** — write findings to `findings/<program>/<finding-slug>.md`
   with: summary, scope reference, reproduction steps, impact, suggested
   fix. This is what actually gets submitted, so it should read like a
   report, not like the agent's internal reasoning log.

## Before every tool call, run the critic gate (see `agents/critic-agent.md`)
Same six questions as HTB mode, plus a seventh that's bug-bounty-specific:
7. Is this host/action actually inside the program's documented scope?
