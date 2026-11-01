---
name: graphql
description: Use when assessing GraphQL schemas, queries, resolvers, field authorization, or API data exposure in an authorized application or lab.
---

# GraphQL Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** GraphQL Security Testing

**Classification:** Often intersects OWASP API Top 10 2023 API1 BOLA, API2 Broken Authentication, API3 Broken Object Property Level Authorization, API4 Unrestricted Resource Consumption

### Root cause

GraphQL centralizes many object and field resolvers behind one endpoint. Security therefore depends on authorization and resource controls being enforced at resolver/object/field boundaries, not merely at the top-level HTTP route. Query structure itself is attacker-controlled execution planning.

### High-signal attack surface

- /graphql, /api/graphql, GraphQL POST bodies, persisted query hashes
- introspection metadata, __typename, Relay node IDs
- nested resolvers, mutations, subscriptions, batching/aliases

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Determine whether introspection is available; if not, infer schema only from your own client traffic and errors.
2. Build a resolver map from queries and mutations used by the application.
3. Test object-level and field-level authorization with two accounts, one field at a time.
4. Test batching, aliases, nested traversal, and mutation inputs for inconsistent checks while staying within rate/resource limits.

### Mutation logic

- Aliases/batching. Reason: middleware may count one HTTP request while executing many resolver operations.
- Nested object traversal. Reason: child resolvers may omit parent authorization context.
- Null/omitted/default input differences. Reason: validation and authorization paths may diverge.
- Global IDs/node resolvers. Reason: generic object lookup can bypass type-specific authorization.

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

- GraphQL BOLA → synthetic cross-account data access
- Field-level auth flaw → sensitive property exposure
- GraphQL mass assignment → unauthorized state change

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

hexstrike-ai is useful for schema inference and resolver relationship mapping. OpenCode can generate typed queries from captured operations and run A/B authorization diffs. Avoid uncontrolled depth/complexity testing.

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

Build a GraphQL API with users, projects, invoices, and admin-only fields. Include intentionally vulnerable node lookup, field resolver, alias batching, and mutation authorization examples.

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
