"""Root resolution, workspace discovery, and small shared helpers.

BB_ROOT may be overridden for tests or for running the CLI against a copied
workspace tree; every module resolves paths through root() rather than
capturing a value at import time.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

ROLE_SPECIALISTS = [
    "recon-agent",
    "web-agent",
    "ad-agent",
    "privesc-agent",
    "linux-privesc-agent",
]
ALL_AGENTS = ["orchestrator", "critic-agent", *ROLE_SPECIALISTS]
MODE_FILES = {"htb": "modes/htb.md", "bounty": "modes/bounty-auto.md",
              "bugbounty": "modes/bugbounty.md"}


def root() -> Path:
    """Repository root. Honors BB_ROOT so tests never touch the real tree."""
    env = os.environ.get("BB_ROOT")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts if ts is not None else now(), timezone.utc).isoformat(
        timespec="seconds")


def slugify(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s[:maxlen].rstrip("-") or "untitled")


def rel(path: Path | str, base: Path | None = None) -> str:
    p = Path(path)
    b = base or root()
    try:
        return str(p.resolve().relative_to(b.resolve()))
    except ValueError:
        return str(p)


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def write_json(path: Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str))
    os.replace(tmp, path)


def discover_workspaces(base: Path | None = None) -> list[Path]:
    """Every directory under the tree containing a state.json."""
    base = base or root()
    found: list[Path] = []
    for pattern in ("labs/*/machines/*/state.json", "programs/*/state.json",
                    "labs/**/state.json", "exercises/**/state.json"):
        found.extend(p.parent for p in base.glob(pattern))
    return sorted(set(found))


def resolve_workspace(spec: str | None, base: Path | None = None) -> Path | None:
    """Resolve a user-supplied workspace name/path.

    Accepts a path, an HTB machine name (labs/HTB/machines/<name>), a bounty
    program slug (programs/<slug>), or an HTB scope json name (programs/htb/*.json
    -> the matching machines/<name> workspace if it exists).
    """
    base = base or root()
    if not spec:
        return None
    p = Path(spec)
    candidates = []
    if p.is_absolute():
        candidates.append(p)
    else:
        candidates += [base / p, Path.cwd() / p, base / "labs" / "HTB" / "machines" / p,
                       base / "programs" / p]
    for c in candidates:
        if c.is_dir() and (c / "state.json").exists():
            return c.resolve()
    for c in candidates:
        if c.is_dir():
            return c.resolve()
    return None


def workspace_for_run(mode: str, workspace: str | None, machine: str | None,
                      target: str | None, program: str | None,
                      base: Path | None = None) -> Path:
    base = base or root()
    if workspace:
        return resolve_workspace(workspace, base) or (Path(workspace) if Path(workspace).is_absolute()
                                                      else base / workspace)
    if mode == "htb":
        name = machine or target or "target"
        return base / "labs" / "HTB" / "machines" / name
    if program:
        return base / "programs" / program
    return base / "programs" / (target or "target")


def load_skill_roots(base: Path | None = None) -> dict:
    base = base or root()
    cfg = read_json(base / "lib" / "skill_roots.json", default={})
    return {
        "packaged_roots": cfg.get("packaged_roots", []),
        "flat_roots": cfg.get("flat_roots", []),
    }


def skills_index_path(base: Path | None = None) -> Path:
    return (base or root()) / ".skills_index.json"


def cache_stamp(base: Path | None = None) -> str:
    """Cheap invalidation stamp: newest mtime across configured roots + config."""
    base = base or root()
    newest = 0.0
    cfg = base / "lib" / "skill_roots.json"
    if cfg.exists():
        newest = cfg.stat().st_mtime
    roots = load_skill_roots(base)
    for name in roots["packaged_roots"] + roots["flat_roots"]:
        d = base / name
        if d.exists():
            newest = max(newest, d.stat().st_mtime)
    return f"{int(newest)}"
