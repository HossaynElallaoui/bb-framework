# Bug Bounty Skill Pack

A modular set of vulnerability-class skills for authorized bug bounty programs, labs, CTFs, and owned test environments.

## Operating model

Every skill follows the same lifecycle:

1. Scope & authorization gate
2. Attack-surface discovery
3. Hypothesis formation
4. Manual validation
5. Controlled automation
6. Evidence collection
7. Escalation / chaining
8. False-positive elimination
9. Reporting
10. Cleanup

## Environment

Designed for:

- Kali Linux
- Burp Suite / Repeater / Intruder / Collaborator where available
- curl, httpx, jq, ffuf, nuclei, sqlmap where appropriate
- hexstrike-ai as an assistant for hypothesis generation, request mutation, clustering, and result triage
- OpenCode as a local coding agent for custom test scripts, parsers, payload generators, and lab harnesses

## Safety / scope discipline

Use only against assets you own or are explicitly authorized to test. Respect program scope, rate limits, prohibited actions, data-handling rules, and stop conditions. Prefer harmless proof-of-concept validation over destructive impact.

## Skill layout

Each vulnerability has its own folder containing `SKILL.md`.


## Included skills

- [SSRF](ssrf/SKILL.md) — Server-Side Request Forgery
- [IDOR-BOLA](idor-bola/SKILL.md) — Insecure Direct Object Reference / Broken Object Level Authorization
- [XXE](xxe/SKILL.md) — XML External Entity Injection
- [Race Conditions](race-conditions/SKILL.md) — Race Conditions / Concurrency Bugs
- [Authentication Bypass](auth-bypass/SKILL.md) — Authentication Bypass
- [SQL Injection](sqli/SKILL.md) — SQL Injection
- [XSS](xss/SKILL.md) — Cross-Site Scripting
- [HTTP Request Smuggling](request-smuggling/SKILL.md) — HTTP Request Smuggling / Desynchronization
- [Web Cache Poisoning](cache-poisoning/SKILL.md) — Web Cache Poisoning / Cache Key Confusion
- [Insecure Deserialization](deserialization/SKILL.md) — Insecure Deserialization
- [OAuth-OIDC](oauth-oidc/SKILL.md) — OAuth 2.x / OpenID Connect Implementation Flaws
- [JWT](jwt/SKILL.md) — JSON Web Token Validation Flaws
- [GraphQL](graphql/SKILL.md) — GraphQL Security Testing
- [File Upload](file-upload/SKILL.md) — File Upload Security
- [Path Traversal](path-traversal/SKILL.md) — Path Traversal / File Path Injection
- [Prototype Pollution](prototype-pollution/SKILL.md) — JavaScript Prototype Pollution
- [SSTI](ssti/SKILL.md) — Server-Side Template Injection
- [CORS](cors/SKILL.md) — Cross-Origin Resource Sharing Misconfiguration
- [Business Logic](business-logic/SKILL.md) — Business Logic Vulnerabilities
