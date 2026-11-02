# BUG BOUNTY MODE — full automation pipeline

This is the throughput-oriented wrapper around `modes/bugbounty.md`. The hard
scope gate and evidence discipline are unchanged; what changes is that every
discovery becomes a scored hypothesis immediately, validation is synchronous,
and the operator can steer or pause a long run without killing it.

## Operating contract

- **Scope is a hard gate, not a suggestion.** Load the program policy before
  anything else: `bb scope-check --program <slug> --full`. Every host/endpoint
  must match an allow rule and no exclusion. Anything unlisted fails closed.
  Scope changes only happen by editing `programs/<slug>/scope.md` or
  `scope.env` deliberately — never by model output or an in-session override.
- **Rate ceiling is central.** `scope.env`'s `BB_RATE_PER_MIN` is enforced by
  `scripts/capture-command.py --workspace`, not by each specialist's self
  discipline. Concurrency is capped by `BB_MAX_CONCURRENCY`. "Faster" never
  means "over the agreed ceiling".
- **Evidence by path.** State and mailbox messages reference
  `evidence/...`; secrets are never pasted into `state.json`.

## Pipeline

1. `bb init <program>` — create the workspace from `programs/_template/`.
2. Fill `programs/<program>/scope.md` (in-scope assets, exclusions, rate,
   required identification header). Optional hard overrides in `scope.env`.
3. `bb scope-check --program <program> --full` — enumerate the policy and
   confirm it is neither empty nor over-broad before any model call.
4. `bb run --mode bounty --workspace programs/<program> --target <first-host> \
   --model <free-model> --parallel 1` — bounty mode defaults to one turn at a
   time unless the policy allows more. Each round re-verifies scope.
5. **Continuous hypotheses.** Every recon observation becomes a scored
   hypothesis immediately (`bb state ... add-hyp`), so `next-hyp` always has a
   fresh cheap candidate. Findings that are not yet claimed live on
   `bb leads` — the board remembers the rest while a hunter focuses on one.
6. **Synchronous validation (engine-enforced).** The moment a hypothesis flips
   to `confirmed`, `bb state ... update-hyp --status confirmed` automatically
   writes a finding skeleton under the workspace `findings/` and runs the 4
   deterministic gates (`is_real` / `in_scope` / `exploitable` / `not_dup`)
   plus the 7-question critic gate on it, recording the outcome in
   `bb_last_validation` and the critic's mailbox. A skeleton starts as
   `confirmed_unvalidated` and fails the evidence gates by design — attach
   evidence and run `bb validate <finding-id>` to flip it. Gate 4 checks the
   local finding registry for duplicates; a live HackerOne Hacktivity
   cross-check is a manual operator step, not a model decision.
   Additionally, every confirm produced by a specialist turn gets a cheap
   second-opinion verifier turn (skeptical system prompt, existing evidence
   only, no new actions); a `VERDICT: KICKBACK` deterministically reverts the
   hypothesis to `open` with the reason in the result and the specialist's
   inbox. Disable with `bb run --no-verify`.
7. **Report draft.** `bb report <finding-id> --workspace <ws>` renders from
   `programs/_template/reports/finding-template.md` with evidence paths. The
   operator reviews and edits; nothing is auto-submitted. Raw secret-looking
   values are redacted and the raw request stays in the evidence path.
8. **Learn unconditionally.** `bb learn --workspace <ws>` extracts candidate
   skills from confirmed hypotheses, the writeup's REUSABLE TECHNIQUE section,
   and clusters of negative results. Review in the dashboard Learn tab or with
   `bb learn --approve <id>`, then `bb learn --commit`. Negative sessions
   produce reusable "this path does not work" skills too.

## Throughput levers that stay safe

- `bb leads` is the operator's triage surface: claim a lead, hand it to a
  worker, mark it killed/parked/reported. The board is flock-safe and
  workspace-scoped.
- `bb next-hyp` ranks with benchmark-calibrated costs; `--apply` writes those
  costs back for hypotheses still using the flat default. This is the fix for
  free models assigning cost=1.0 to everything.
- The dashboard shows the same ranking, a chronological Timeline, a pause
  sentinel, and learn-candidate approvals. It reads the same `state.json`, so
  it never disagrees with the CLI.
- Stall warnings fire early (actions-since-milestone and dead-end-rate, both
  calibrated from the Connected vs Autopilot benchmark runs), not after a
  29-hour pathological loop.

## Stop conditions

Stop the whole run the instant any of these is true, and mark it at the moment
it becomes true (keep-first milestones):

- `root` (HTB) / `flag` (HTB) / `validated-finding` (bounty)
- scope gate flips to DENY
- operator pause sentinel
- hypothesis queue is empty and recon has produced nothing new for two rounds

A resume must pick up mid-hypothesis with zero re-work:
`bb run --resume programs/<program>`.
