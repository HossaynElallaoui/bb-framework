# Composite action bundles — one turn per standard chain

Turn count is the dominant cost driver. These bundles wrap a known
multi-step sequence in a single `capture-command.py` invocation so one turn
runs the whole chain and returns sectioned output. Prefer a bundle over N
single-step turns whenever the situation matches; fall back to individual
commands only when you need something the bundle does not cover.

## Catalog

| name | usage | replaces |
|---|---|---|
| web-recon | `web-recon.sh <base-url> [wordlist]` | headers + whatweb + robots/sitemap + shallow dir scan (~4 turns) |
| ad-enum | `ad-enum.sh <dc-ip> [domain.fqdn]` | netexec SMB/signing/shares + LDAP rootDSE + DNS A/AXFR/SRV + kerberos probe (~6 turns) |
| lin-privesc | `lin-privesc.sh` | sudo -l + SUID + capabilities + cron + writable unit paths + dangerous groups + credential classics (~7 turns) |

## Invocation (evidence discipline applies)

```bash
python3 scripts/capture-command.py <evidence-dir> --workspace $BB_WORKSPACE -- \
  composites/web-recon.sh https://target.htb
```

`bb composite list` shows the registered bundles and script health;
`bb composite show <name>` shows usage details. The manifest lives in
`composites/manifest.json`; add a bundle by writing the script and
registering it there — the skill index picks up this file automatically.

## Output contract

Every bundle prints `=== <section> ===` markers so the result summary can be
recorded per-section in state (`record-action --summary`), and a missing tool
prints `skipped: ...` instead of failing the whole bundle.
