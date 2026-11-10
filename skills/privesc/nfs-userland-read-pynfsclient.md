# NFS export read without root (userland pyNfsClient)

Trigger: a host exposes NFS (111/rpcbind + 2049) and `showmount -e` lists an
export, but you have no root/sudo to `mount` it and no libnfs CLI tools
(`nfs-ls`, `nfs-cat`) installed. Read files straight over NFSv3 RPC as an
unprivileged user.

1. Confirm the export: `showmount -e <host>` (e.g. `/srv/nfs/onboarding *`).
2. Use the distro package (Kali/Debian: `python3-pyNfsClient`, import name
   `pyNfsClient`). No mount, no CAP_SYS_ADMIN.
3. Connect portmapper, ask for mountd (program 100005, version 3), then
   `Mount.mnt(export)`. The result contains `mountinfo.fhandle` (bytes).
4. `NFSv3(host, 2049, timeout, auth).lookup(root_fh, name)` then
   `read(fh, offset=...)` in a loop until `resok.eof`.
5. AUTH_SYS auth is a dict:
   `{"flavor":1,"machine_name":"kali","uid":1000,"gid":1000,"aux_gid":[0]}`
   (a root uid is squashed on many exports; try 1000 for world-readable files).
6. `lookup` returns the file handle as `resok.object["data"]` (a dict, not
   bytes); `readdir` returns nested `nextentry` lists, and names are bytes.

Working script: `labs/HTB/machines/enigma/nfs_read.py` (host, export, remote
file, local out).

Pitfalls:
- `RPC.connect()` must be called before any request; `client` is None otherwise.
- `mount.nfs` setuid does not grant mount privileges for unlisted users; it
  fails with `failed to apply fstab options` (exit 32). Don't assume a setuid
  mount helper means you can mount.
- Tool-level external-directory restrictions may block reading an existing
  `/mnt/<export>` mount; the userland reader needs no local path at all.
- Look in documents first: onboarding PDFs/READMEs commonly carry credentials.
