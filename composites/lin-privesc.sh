#!/usr/bin/env bash
# composite: lin-privesc — standard local Linux privesc sweep in ONE turn.
# usage: lin-privesc.sh   (run on the target shell)
set -u

section() { printf '\n=== %s ===\n' "$1"; }

section "identity"
id 2>&1; uname -r 2>&1; hostname 2>&1

section "sudo"
sudo -n -l 2>&1 | head -30 || echo "(sudo requires a password or is unavailable)"

section "suid"
find / -xdev -perm -4000 -type f 2>/dev/null | head -30

section "capabilities"
command -v getcap >/dev/null && getcap -r / 2>/dev/null | head -20 \
  || echo "skipped: getcap not installed"

section "cron"
ls -la /etc/cron* 2>/dev/null | head -20
cat /etc/crontab 2>/dev/null | head -10

section "writable-service-paths"
find /etc/systemd/system /lib/systemd/system -user "$(id -un)" -o -group "$(id -gn)" -perm -o+w -type f 2>/dev/null | head -15

section "groups"
for g in docker lxd disk adm wheel sudo; do id -nG 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && echo "member of: $g"; done

section "creds-classics"
ls -la /etc/shadow 2>/dev/null
grep -RIsE "(password|passwd|secret|api[_-]?key).{0,40}" /opt /srv /var/www 2>/dev/null | head -10

section "done"
