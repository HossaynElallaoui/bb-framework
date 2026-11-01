#!/usr/bin/env python3
"""One-time migration: unify run writeup filenames to `writeup.md`.

Renames WRITEUP.md / postmortem.md -> writeup.md only when no writeup.md
already exists. Conflicts are reported and left untouched. Never overwrites.

    python3 scripts/migrate_writeups.py --dry-run
    python3 scripts/migrate_writeups.py
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ("WRITEUP.md", "postmortem.md")


def workspaces(root: Path):
    seen = set()
    for pattern in ("labs/*/machines/*", "programs/*", "exercises/*"):
        for p in root.glob(pattern):
            if p.is_dir() and p not in seen and (p / "state.json").exists():
                seen.add(p)
                yield p


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    renamed = conflicts = 0
    for ws in workspaces(root):
        target = ws / "writeup.md"
        legacy = [n for n in LEGACY if (ws / n).exists()]
        if not legacy:
            continue
        if target.exists():
            print(f"CONFLICT {ws.relative_to(root)}: writeup.md and {legacy} coexist — left untouched")
            conflicts += 1
            continue
        src = ws / legacy[0]
        if args.dry_run:
            print(f"would rename {src.relative_to(root)} -> writeup.md")
        else:
            os.replace(src, target)
            print(f"renamed {src.relative_to(root)} -> writeup.md")
        renamed += 1
    print(f"\n{'would rename' if args.dry_run else 'renamed'}: {renamed}, conflicts: {conflicts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
