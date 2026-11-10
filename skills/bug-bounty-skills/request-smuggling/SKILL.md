# HTTP Request Smuggling Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** HTTP Request Smuggling / Desynchronization

**Classification:** CWE-444; commonly arises from inconsistent HTTP parsing between front-end and back-end components

### Root cause

The vulnerability exists when two HTTP components disagree about request boundaries. One component decides where request A ends differently from the next component, allowing bytes to be interpreted as part of a subsequent request. Modern variants also involve HTTP/2-to-HTTP/1 translation and header normalization.

### High-signal attack surface

- reverse proxies/CDNs/load balancers in front of different backend servers
- HTTP/1.1 downgrade paths, ambiguous Transfer-Encoding/Content-Length handling
- different behavior through direct backend versus edge in a controlled lab

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Use a purpose-built local proxy/backend lab first to understand parser disagreement.
2. On authorized targets, begin with non-invasive timing/desync indicators and strict request limits.
3. Compare CL/TE interpretation only when the program allows this class of testing because mistakes can affect other users.
4. Stop if any evidence suggests cross-user interference or service instability.

### Mutation logic

- CL.TE / TE.CL structure in isolated labs. Reason: each hop may prioritize different framing rules.
- Whitespace/header-name normalization. Reason: parsers may disagree on whether a transfer-encoding header is valid.
- HTTP/2 translation edge cases. Reason: pseudo-headers and downgraded framing can create new disagreement classes.

### Burp workflow

- Proxy one clean baseline flow and save it.
- Send the minimal candidate request to Repeater.
- Change exactly one security-relevant variable at a time.
- Use Comparer or structured response diffing when differences are subtle.
- Use Intruder only after you understand the variable and can keep request volume within scope.
- Preserve request/response pairs that prove both baseline and vulnerable behavior.

### Kali baseline

```bash
export TARGET='https://authorized-target.example'
# Passive/low-impact endpoint inventory from URLs you already possess:
printf '%s\n' "$TARGET" | httpx -silent -title -status-code -tech-detect
# Use curl for deterministic request reproduction:
curl -isk "$TARGET/known-path"
```

Do not interpret a scanner hit as a finding. Reproduce manually and explain the security invariant that failed.

## Real-world methodology

1. Start from application features, not vulnerability names.
2. Build an endpoint/parameter/state map from normal application use.
3. Label data origins: user input, headers, path variables, stored content, third-party callbacks, imported documents, tokens, client state.
4. Label security decisions: authentication, authorization, validation, canonicalization, routing, caching, transaction boundaries.
5. Prioritize places where one layer validates and another layer consumes.
6. Test alternate clients and forgotten surfaces: mobile APIs, old versions, exports/imports, background jobs, websocket/GraphQL endpoints, admin previews, and integrations—only when in scope.

## Advanced escalation

Potential authorized lab chains:

- Desync → cache poisoning in lab
- Desync → request routing confusion
- H2 downgrade discrepancy → backend request ambiguity

Escalation rule: move to the next step only if it proves a distinct business/security impact. Do not expand blast radius merely to make the finding look more severe.

## Elite thinking

For each target, maintain a hypothesis table:

| Observation | Hypothesis | Minimal experiment | Expected secure behavior | Evidence |
|---|---|---|---|---|
| Feature accepts attacker-controlled state | A downstream component may trust a different representation | Change one representation while preserving semantics | Request is normalized and rejected/authorized consistently | Request + response + server-visible state |

Ask continuously:

- What assumption is the developer making here?
- Which layer enforces it?
- Is that enforcement applied to every alternate path?
- What representation reaches the security check versus the final consumer?
- What happens on retries, redirects, asynchronous jobs, or cross-service calls?
- What can two valid features do together that neither feature can do alone?

## hexstrike-ai role

hexstrike-ai may help reason about proxy chains, but never let it mass-test desync payloads. Use OpenCode to build a local raw-socket parser lab and request visualizer. On real programs, prefer Burp's dedicated tooling and conservative manual confirmation if explicitly permitted.

Use AI for clustering, hypothesis generation, transformation analysis, response diffing, and code/test generation. Do not delegate scope decisions or vulnerability confirmation to the model.

## OpenCode tasks

Good tasks for OpenCode:

- Build a request corpus from sanitized Burp exports.
- Generate a one-variable-at-a-time mutation harness.
- Normalize JSON/HTML responses before diffing.
- Add rate limiting, retry limits, structured logs, and a dry-run mode.
- Generate unit tests that encode the expected secure invariant.
- Build a local vulnerable/fixed pair for the behavior under study.

## Full test environment

Run a front-end proxy and backend server with intentionally mismatched HTTP parsing rules on an isolated Docker network. Add request logs on both sides so boundary disagreement is visible.

Recommended topology:

```text
Kali / Burp / hexstrike-ai / OpenCode
              |
        isolated lab network
              |
       vulnerable application
          /          \
 mock dependency   evidence logger
```

Keep the lab isolated from production networks and seed it only with synthetic secrets/accounts/data.

## Evidence checklist

- Exact affected endpoint and method
- Preconditions/account role
- Baseline request/response
- Modified request/response
- Server-side final state if relevant
- Why the behavior violates a security invariant
- Minimal impact demonstration
- False-positive controls
- Remediation at the correct trust boundary

## Stop conditions

Stop testing if you observe service instability, unexpected access to real user data, cross-user interference, irreversible state changes, or behavior forbidden by the program rules.
