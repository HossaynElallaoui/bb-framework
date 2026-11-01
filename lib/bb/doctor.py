"""Environment doctor, MANIFEST generator, and one-time cleanup helpers.

Checks are deterministic and offline. `--fix` only performs explicitly safe,
reversible actions (writeup renames); root-owned directory removal requires
`--yes` and is reported, never silent.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from lib.bb import config, statex

OK, WARN, FAIL = "ok", "warn", "fail"


def _run(cmd: list[str], timeout: float = 5) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def _which(name: str) -> str | None:
    return shutil.which(name)


def check_python() -> dict:
    v = sys.version.split()[0]
    ok = sys.version_info >= (3, 9)
    return {"status": OK if ok else FAIL, "name": "python",
            "detail": f"{v} ({sys.executable})"}


def check_rich() -> dict:
    try:
        import rich  # noqa: F401
        return {"status": OK, "name": "rich", "detail": "installed (terminal UI enabled)"}
    except Exception as e:
        return {"status": WARN, "name": "rich",
                "detail": f"missing ({e}) — falls back to plain output"}


def check_opencode() -> dict:
    path = _which("opencode")
    if not path:
        return {"status": FAIL, "name": "opencode", "detail": "not found on PATH"}
    rc, out = _run([path, "--version"])
    return {"status": OK if rc == 0 else WARN, "name": "opencode",
            "detail": f"{path} — {out.splitlines()[0] if out else 'version unknown'}"}


def check_httpx() -> dict:
    """The classic Go-vs-Python shadowing gotcha."""
    path = _which("httpx")
    go_path = "/home/kali/go/bin/httpx"
    if not path:
        return {"status": WARN, "name": "httpx", "detail":
                f"not on PATH (expected Go binary at {go_path})"}
    real = str(Path(path).resolve())
    rc, out = _run([path, "-version"])
    if rc != 0:
        rc, out = _run([path, "--version"])
    low = out.lower()
    looks_go = ("projectdiscovery" in low or "current version" in low
                or ("httpx version" in low and "python" not in low))
    # A tiny script with a python shebang is the classic shadowing culprit
    # (/usr/bin/httpx is 205 bytes here, while the Go build is ~70 MB).
    is_script = False
    shebang = ""
    try:
        with open(real, "rb") as fh:
            head = fh.read(120)
        is_script = head.startswith(b"#!")
        shebang = head.split(b"\n", 1)[0].decode("utf-8", "replace")
    except OSError:
        pass
    looks_py = ("python-httpx" in low or "python httpx" in low
                or "python" in shebang.lower()
                or real.endswith(("/site-packages/httpx", "/httpx/__main__.py")))
    go_exists = Path(go_path).exists()
    if looks_py or ("python" in real.lower() and "go/bin" not in real):
        hint = f"; the ProjectDiscovery build is at {go_path}" if go_exists else ""
        return {"status": WARN, "name": "httpx", "detail":
                f"python-httpx is winning ({real}{', ' + shebang if shebang else ''}){hint} "
                f"— fix PATH order"}
    if looks_go:
        return {"status": OK, "name": "httpx", "detail": f"Go binary: {real}"}
    if go_exists and real != str(Path(go_path).resolve()):
        return {"status": WARN, "name": "httpx", "detail":
                f"resolved to {real} (small wrapper?); Go build exists at {go_path} — check PATH order"}
    return {"status": WARN, "name": "httpx",
            "detail": f"resolved to {real}; could not prove it is the ProjectDiscovery Go build"}


def check_mcp(host: str = "127.0.0.1", port: int = 8888) -> dict:
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {"status": OK, "name": "hexstrike-mcp",
                    "detail": f"{host}:{port} accepting connections"}
    except OSError as e:
        return {"status": WARN, "name": "hexstrike-mcp",
                "detail": f"{host}:{port} unreachable ({e})"}


def check_mcp_routes(host: str = "127.0.0.1", port: int = 8888) -> dict:
    """Diff the endpoint strings in the MCP client against the server's route
    table. Prefers openapi.json, then the Flask source (this HexStrike build
    does not expose openapi). Catches the 404 mismatch class before a turn
    burns tokens."""
    import json as _json
    import re as _re
    import urllib.request as _url
    client = Path("/home/kali/hexstrike-ai-update/hexstrike_mcp.py")
    server_src = Path("/home/kali/hexstrike-ai-update/hexstrike_server.py")
    try:
        text = client.read_text(errors="ignore")
        paths = set(_re.findall(
            r'["\']/?(api/[a-z0-9_./-]+)["\']', text))
    except OSError:
        return {"status": WARN, "name": "mcp-routes",
                "detail": f"client not readable at {client}; cannot diff routes"}
    server: set[str] = set()
    source = "openapi.json"
    try:
        with _url.urlopen(f"http://{host}:{port}/openapi.json", timeout=2) as r:
            spec = _json.loads(r.read().decode())
        server = {p.rstrip("/") for p in (spec.get("paths") or {})
                  if p.startswith("/api/")}
    except Exception:
        source = "Flask source"
        try:
            src = server_src.read_text(errors="ignore")
            server = {m.rstrip("/") for m in _re.findall(
                r'@app\.route\(["\'](/api/[^"\']+)', src)}
        except OSError:
            return {"status": WARN, "name": "mcp-routes",
                    "detail": f"no openapi and server source unreadable; "
                              f"client has {len(paths)} /api path(s)"}
    if not server:
        return {"status": WARN, "name": "mcp-routes",
                "detail": f"no server routes found via {source}; "
                          f"client has {len(paths)} /api path(s)"}
    missing = sorted(p for p in paths if "/" + p.rstrip("/") not in server)
    if missing:
        return {"status": WARN, "name": "mcp-routes",
                "detail": f"{len(missing)}/{len(paths)} client path(s) absent from "
                          f"server ({source}): {', '.join(missing[:10])}"}
    return {"status": OK, "name": "mcp-routes",
            "detail": f"all {len(paths)} client /api path(s) exist in server ({source})"}


def check_mcp_registration() -> dict:
    """Check opencode's MCP block. This proves config, not that the current
    process loaded the tools; the latter needs an opencode session probe."""
    import json as _json
    cfg = Path.home() / ".config" / "opencode" / "opencode.json"
    try:
        data = _json.loads(cfg.read_text())
    except OSError:
        return {"status": WARN, "name": "mcp-registration",
                "detail": f"{cfg} not readable"}
    except ValueError as e:
        return {"status": FAIL, "name": "mcp-registration",
                "detail": f"{cfg} invalid JSON: {e}"}
    servers = data.get("mcp") or {}
    hs = servers.get("hexstrike") or servers.get("hexstrike-ai")
    if not hs:
        return {"status": WARN, "name": "mcp-registration",
                "detail": f"no hexstrike MCP server in {cfg}; configured: "
                          f"{', '.join(sorted(servers)) or '(none)'}"}
    kind = "remote" if (hs.get("url") or hs.get("type") == "remote") else "local"
    return {"status": OK, "name": "mcp-registration",
            "detail": f"hexstrike registered ({kind}); verify tools with: "
                      f"opencode mcp list"}


def check_skill_roots(base: Path) -> dict:
    roots = config.load_skill_roots(base)
    missing = []
    counts = {}
    for name in roots["packaged_roots"]:
        d = base / name
        if not d.exists():
            missing.append(name)
            continue
        counts[name] = len(list(d.rglob("SKILL.md")))
    for name in roots["flat_roots"]:
        d = base / name
        if not d.exists():
            missing.append(name)
            continue
        counts[name] = sum(1 for p in d.rglob("*.md")
                           if p.name.upper() != "SKILL.MD" and p.name != "README.md")
    total = sum(counts.values())
    if missing:
        return {"status": WARN, "name": "skill-roots",
                "detail": f"missing: {', '.join(missing)}; counts={counts}"}
    return {"status": OK, "name": "skill-roots",
            "detail": f"{len(counts)} roots, {total} skill files: {counts}"}


def check_writeups(base: Path) -> tuple[dict, dict]:
    ws = config.discover_workspaces(base)
    drift = []
    for w in ws:
        names = [n for n in ("writeup.md", "WRITEUP.md", "postmortem.md") if (w / n).exists()]
        if len(names) > 1 or (names and "writeup.md" not in names):
            drift.append({"workspace": config.rel(w, base), "files": names})
    if drift:
        return ({"status": WARN, "name": "writeup-convention",
                 "detail": f"{len(drift)} workspace(s) not using writeup.md: "
                           f"{', '.join(d['workspace'] for d in drift[:6])}"}, {"drift": drift})
    return ({"status": OK, "name": "writeup-convention",
             "detail": f"all {len(ws)} workspace(s) consistent (or none yet)"}, {"drift": []})


def migrate_writeups(drift: list[dict], base: Path, apply: bool = False) -> list[str]:
    actions = []
    for d in drift:
        w = base / d["workspace"]
        target = w / "writeup.md"
        if target.exists():
            actions.append(f"keep {d['workspace']}/writeup.md (conflict with {d['files']})")
            continue
        src_name = next((n for n in ("WRITEUP.md", "postmortem.md") if (w / n).exists()), None)
        if not src_name:
            continue
        if apply:
            os.replace(w / src_name, target)
            actions.append(f"renamed {d['workspace']}/{src_name} -> writeup.md")
        else:
            actions.append(f"would rename {d['workspace']}/{src_name} -> writeup.md")
    return actions


def check_root_owned_burp(base: Path) -> dict:
    found = []
    for name in ("Burp-Suite", "Burpsuite-Professional"):
        p = base / name
        if not p.exists():
            continue
        try:
            st = p.stat()
            if st.st_uid == 0 and os.geteuid() != 0:
                found.append(f"{name} (root-owned)")
        except OSError:
            pass
    if found:
        return {"status": WARN, "name": "burp-leftovers",
                "detail": f"{', '.join(found)} — flagged, not deleted; remove deliberately"}
    return {"status": OK, "name": "burp-leftovers", "detail": "none flagged"}


def check_workspaces(base: Path) -> dict:
    ws = config.discover_workspaces(base)
    interrupted = []
    for w in ws:
        bad, why = statex.is_interrupted(w)
        if bad:
            interrupted.append(f"{config.rel(w, base)}: {why}")
    if interrupted:
        return {"status": WARN, "name": "workspaces",
                "detail": f"{len(interrupted)} interrupted: " + "; ".join(interrupted[:5])}
    return {"status": OK, "name": "workspaces", "detail": f"{len(ws)} workspace(s), none interrupted"}


def find_empty_markers(base: Path) -> list[Path]:
    markers = []
    for p in base.glob("sessionresume_*"):
        if p.is_file() and p.stat().st_size == 0:
            markers.append(p)
    for sub in ("findings", "labs", "programs", "agent_logs"):
        d = base / sub
        if not d.exists():
            continue
        for p in d.rglob("sessionresume_*"):
            if p.is_file() and p.stat().st_size == 0:
                markers.append(p)
    return markers


def check_empty_markers(base: Path) -> dict:
    markers = find_empty_markers(base)
    if markers:
        shown = ", ".join(config.rel(p, base) for p in markers[:5])
        return {"status": WARN, "name": "empty-markers",
                "detail": f"{len(markers)} zero-byte sessionresume_* marker(s): {shown}"}
    return {"status": OK, "name": "empty-markers", "detail": "none"}


def manifest(base: Path | None = None, write: bool = True) -> dict:
    base = base or config.root()
    roots = config.load_skill_roots(base)
    skill_counts = {}
    total = 0
    for name in roots["packaged_roots"]:
        d = base / name
        skill_counts[name] = len(list(d.rglob("SKILL.md"))) if d.exists() else 0
        total += skill_counts[name]
    for name in roots["flat_roots"]:
        d = base / name
        n = sum(1 for p in d.rglob("*.md")
                if p.name.upper() != "SKILL.MD" and p.name != "README.md") if d.exists() else 0
        skill_counts[name] = n
        total += n

    def count_dir(rel: str, pattern: str) -> int:
        d = base / rel
        return len(list(d.glob(pattern))) if d.exists() else 0

    from lib.bb import __version__
    data = {
        "generated_at": config.iso(),
        "bb_version": __version__,
        "python": sys.version.split()[0],
        "opencode": (_run([_which("opencode") or "opencode", "--version"])[1].splitlines() or [""])[0],
        "skills": {"roots": skill_counts, "total": total},
        "commands": {"agentic_bug_hunter": count_dir("agentic-bug-hunter/commands", "*.md")},
        "agents": sum(1 for p in (base / "agents").glob("*.md")
                      if not p.name.startswith("_")) if (base / "agents").exists() else 0,
        "modes": count_dir("modes", "*.md"),
        "scripts": count_dir("scripts", "*.py"),
        "programs": sorted(p.name for p in (base / "programs").glob("*")
                           if p.is_dir() and not p.name.startswith("_")),
        "note": "Counts are generated from disk; edit docs to match this file.",
    }
    if write:
        config.write_json(base / "MANIFEST.json", data)
    return data


def run(base: Path | None = None, *, fix_writeups: bool = False,
        fix_markers: bool = False, remove_root_burp: bool = False, yes: bool = False,
        manifest_out: bool = True) -> list[dict]:
    base = base or config.root()
    checks = [
        check_python(), check_rich(), check_opencode(), check_httpx(),
        check_mcp(), check_mcp_routes(), check_mcp_registration(),
        check_skill_roots(base), check_root_owned_burp(base),
        check_empty_markers(base),
    ]
    wcheck, extra = check_writeups(base)
    checks.append(wcheck)
    checks.append(check_workspaces(base))

    if fix_writeups and extra["drift"]:
        actions = migrate_writeups(extra["drift"], base, apply=True)
        checks.append({"status": OK, "name": "writeup-migration",
                       "detail": "; ".join(actions) or "nothing to do"})
        # re-evaluate the convention check against the post-migration tree
        checks = [c for c in checks if c["name"] != "writeup-convention"]
        checks.append(check_writeups(base)[0])
    elif extra["drift"]:
        actions = migrate_writeups(extra["drift"], base, apply=False)
        checks.append({"status": WARN, "name": "writeup-migration",
                       "detail": "dry-run: " + "; ".join(actions) if actions else "nothing to do"})

    if fix_markers:
        removed = []
        for p in find_empty_markers(base):
            try:
                p.unlink()
                removed.append(config.rel(p, base))
            except OSError:
                pass
        checks = [c for c in checks if c["name"] != "empty-markers"]
        checks.append(check_empty_markers(base))
        checks.append({"status": OK if removed else WARN, "name": "marker-cleanup",
                       "detail": f"removed {len(removed)} zero-byte marker(s)" if removed
                                 else "no empty markers to remove"})

    if remove_root_burp and yes:
        removed = []
        for name in ("Burp-Suite",):
            p = base / name
            if p.exists() and p.stat().st_uid == 0 and os.geteuid() != 0:
                try:
                    shutil.rmtree(p)
                    removed.append(name)
                except OSError as e:
                    checks.append({"status": WARN, "name": "burp-removal",
                                   "detail": f"could not remove {name}: {e}"})
            elif p.exists():
                checks.append({"status": WARN, "name": "burp-removal",
                               "detail": f"{name} is not root-owned; refusing automatic removal"})
        if removed:
            checks.append({"status": OK, "name": "burp-removal",
                           "detail": f"removed {', '.join(removed)}"})

    if manifest_out:
        data = manifest(base, write=True)
        checks.append({"status": OK, "name": "manifest",
                       "detail": f"MANIFEST.json written ({data['skills']['total']} skills)"})
    return checks
