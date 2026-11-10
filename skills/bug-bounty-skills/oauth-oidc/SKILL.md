# OAuth-OIDC Skill


## Scope gate

Use this skill only on assets you own, intentionally vulnerable labs/CTFs, or bug-bounty targets where the technique is explicitly permitted. Read program rules first. Use dedicated accounts and synthetic data. Prefer the least invasive proof that establishes the issue.

## Core foundations

**Class:** OAuth 2.x / OpenID Connect Implementation Flaws

**Classification:** Often maps to OWASP A07 Identification and Authentication Failures / A01 Broken Access Control; relevant OAuth/OIDC specifications define protocol requirements

### Root cause

OAuth delegates authorization and OIDC adds identity. Security depends on binding the authorization response to the initiating browser session, client, redirect URI, code verifier, issuer, audience, and nonce. Bugs arise when one of these bindings is absent, weak, or inconsistently enforced.

### High-signal attack surface

- /authorize, /token, /callback, /.well-known/openid-configuration
- social login, enterprise SSO, multiple redirect URIs and clients
- state, nonce, PKCE, code, id_token, access_token parameters

## Deep technical internals

For every candidate endpoint, answer these questions before sending aggressive tests:

1. Which component receives the attacker-controlled value first?
2. Which normalization/parsing steps transform it?
3. Which component makes the security decision?
4. Which component ultimately consumes the value?
5. Can those components disagree about identity, syntax, authority, state, or canonical form?

Treat the data-flow and trust-boundary diagram as part of the exploit, not documentation after the fact.

## Lab-level exploitation workflow

1. Map actors: user-agent, client, authorization server, resource server, and every redirect URI.
2. Record a clean authorization-code+PKCE flow and label state, nonce, code_verifier, client_id, redirect_uri, issuer, and audience.
3. Test each binding independently with dedicated test accounts: replay, omission, substitution, wrong client/redirect, wrong issuer, and stale state where permitted.
4. Confirm account-linking behavior separately; many severe bugs live in linking rather than login.

### Mutation logic

- state/nonce omission or cross-session substitution. Reason: tests CSRF/replay bindings.
- redirect_uri normalization variants. Reason: exact matching is a central trust boundary.
- client/issuer confusion. Reason: multi-provider systems may accept tokens/codes from an unintended authority.
- PKCE mismatch/reuse. Reason: verifies authorization-code possession binding.

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

- OAuth CSRF → session/account confusion in lab
- Weak account linking → synthetic account takeover
- Issuer/audience confusion → cross-client authentication flaw

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

hexstrike-ai can diagram protocol state and compare flows. OpenCode can parse redirects/JWT claims and produce a state-transition table. Keep testing to your own accounts and approved redirect endpoints.

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

Run a local identity provider plus two relying-party clients, then intentionally weaken state, nonce, redirect matching, PKCE, and account-linking checks one at a time.

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
