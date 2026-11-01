---
name: idor-bola
description: Use when testing object identifiers, cross-account access, ownership enforcement, or IDOR and BOLA in an authorized application using dedicated test accounts.
---

# IDOR-BOLA Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** Insecure Direct Object Reference / Broken Object Level Authorization

**Classification:** OWASP Top 10 2021 A01: Broken Access Control; OWASP API Security Top 10 2023 API1: BOLA; CWE-639

### Root cause

Authentication answers who the caller is; object authorization answers whether that identity may perform this operation on this specific object. BOLA exists when code resolves an attacker-controlled object identifier and performs the action without binding the object lookup to the caller's permitted tenant, owner, role, or relationship.

### High-signal attack surface

- numeric IDs, UUIDs, slugs, filenames, order IDs, invoice IDs, organization IDs
- REST paths such as /users/{id}, /orders/{id}; GraphQL node identifiers; mobile/API endpoints
- responses where object identifiers are exposed in lists, exports, notifications, or client-side state

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Create two test accounts A and B with distinct objects. Record a baseline request from A to A-owned data and B to B-owned data.
2. Replay A's request while substituting only B's object identifier. Keep every other variable constant.
3. Repeat independently for read, update, delete, export, nested resources, bulk operations, and alternate HTTP methods where authorized.
4. Test tenant boundaries separately from user boundaries; authorization bugs often differ by relationship type.

### Mutation logic

- Identifier substitution. Reason: isolates authorization from request-shape changes.
- Parent/child mismatch, e.g. /org/A/project/B. Reason: applications may authorize the parent but trust the child reference.
- Bulk arrays and GraphQL aliases. Reason: batch resolvers sometimes skip per-object checks.
- Indirect identifiers from exports, logs, notification links, or hidden fields. Reason: obscurity is not authorization.

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

- BOLA → PII exposure using only synthetic lab data
- BOLA → horizontal privilege escalation
- BOLA + mass assignment → unauthorized modification

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

Use hexstrike-ai to infer identifier relationships and propose A/B request pairs. Use OpenCode to build a differential-response harness that compares status, body structure, length, and semantic fields while preserving cookies/tokens per test account.

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

Build a local API with users, organizations, invoices, and projects. Implement one secure endpoint using owner-scoped queries and one intentionally vulnerable endpoint using a global object lookup. Add read/write/delete variants.

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
