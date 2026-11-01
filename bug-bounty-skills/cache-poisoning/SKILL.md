---
name: cache-poisoning
description: Use when investigating cache keys, unkeyed inputs, cached responses, or web cache poisoning in an authorized application or isolated lab.
---

# Web Cache Poisoning Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** Web Cache Poisoning / Cache Key Confusion

**Classification:** Commonly related to cache key design and HTTP normalization; CWE-444/CWE-525 may be relevant depending on mechanism

### Root cause

Caching creates a split between the request attributes used to generate a response and those used to identify the cached object. Poisoning occurs when attacker-influenced input affects the generated response but is absent or normalized differently in the cache key, allowing that response to be served to other requests.

### High-signal attack surface

- CDNs/reverse-proxy caches, Age/X-Cache/Cache-Control/Vary headers
- responses reflecting headers or query parameters that appear unkeyed
- host/scheme/forwarding-header dependent absolute URLs or redirects

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Determine whether a response is actually cached and how to recognize hits/misses.
2. Map cache-key inputs using harmless unique markers and one variable at a time.
3. Test suspected unkeyed inputs only against a cache-buster path/query in authorized environments.
4. Confirm persistence and scope without exposing other users; prefer dedicated test paths/accounts.

### Mutation logic

- Forwarding headers. Reason: origin apps may trust them while caches ignore them.
- Query normalization/order. Reason: cache and application may canonicalize differently.
- Path decoding. Reason: edge and origin may disagree on encoded separators or delimiters.
- Vary behavior. Reason: missing or incomplete variation can mix response representations.

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

- Cache poisoning → stored-like XSS effect in lab
- Cache confusion → security-header weakening
- Poisoned redirect → controlled navigation in lab

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

Use OpenCode to build a cache-key differential tester that adds unique cache busters and records Age/Vary/X-Cache changes. hexstrike-ai can rank candidate unkeyed inputs from traffic.

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

Create a caching reverse proxy in front of an app that reflects selected headers and query values. Configure secure and intentionally incomplete cache keys for comparison.

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
