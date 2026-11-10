# SSRF Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** Server-Side Request Forgery

**Classification:** OWASP Top 10 2021 A10: Server-Side Request Forgery; CWE-918

### Root cause

The trust boundary fails when attacker-controlled input influences a server-side network request. The interesting layer is not the browser but the application HTTP client, URL parser, DNS resolver, redirect handler, proxy configuration, and destination allow/deny logic. Parser disagreement and normalization are common sources of bypasses.

### High-signal attack surface

- URL importers, webhook testers, avatar/image fetchers, PDF/screenshot generators
- parameters named url, uri, endpoint, callback, webhook, feed, image, proxy, return, next
- server-side integrations that resolve or fetch user-controlled locations

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Establish whether the application performs the request server-side using a controlled callback endpoint or a local lab listener.
2. Vary scheme, hostname representation, redirects, ports, and URL structure one dimension at a time; record exactly which parser decision changes behavior.
3. Test validation-before-redirect and validation-before-DNS-resolution assumptions using harmless controlled infrastructure.
4. Separate blind SSRF from non-blind SSRF by testing timing, callback, and response reflection independently.

### Mutation logic

- Hostname normalization: case, trailing dot, encoded delimiters, IPv4/IPv6 textual forms. Reason: validators and network libraries may canonicalize differently.
- Redirect chains. Reason: validation may occur only on the first URL while the fetcher follows redirects.
- Scheme changes. Reason: libraries may support more protocols than application developers expect.
- DNS behavior. Reason: allowlists based on initial resolution may diverge from the address actually used later.

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

- SSRF → cloud metadata exposure in a dedicated lab
- SSRF → internal admin/API reachability
- SSRF → credential/token exposure → authenticated API testing

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

Use hexstrike-ai to cluster URL-taking endpoints and generate parser-differential hypotheses, not to spray internal IP ranges. Have OpenCode build a small callback logger and a mutation generator that only targets your lab or explicitly authorized endpoints.

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

Create a three-service local lab: vulnerable web app, callback server, and a mock internal HTTP service on an isolated Docker network. The vulnerable app should fetch a submitted URL and expose toggles for allowlist, redirect following, and DNS resolution timing.

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
