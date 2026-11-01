#!/usr/bin/env python3
"""Offline end-to-end test for the `bb` CLI.

Builds a throwaway root (BB_ROOT), exercises every deterministic command, and
never invokes a model (run uses --dry-run). Exits non-zero on the first failed
assertion.

    python3 scripts/smoke_test_bb.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REAL = Path(__file__).resolve().parent.parent
BB = REAL / "bb"


def run(root: Path, *args, expect: int | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["BB_ROOT"] = str(root)
    r = subprocess.run([sys.executable, str(BB), *args], capture_output=True, text=True,
                       env=env, cwd=str(cwd or root))
    if expect is not None and r.returncode != expect:
        raise AssertionError(
            f"`bb {' '.join(args)}` exited {r.returncode}, expected {expect}\n"
            f"STDOUT:\n{r.stdout[-2000:]}\nSTDERR:\n{r.stderr[-2000:]}")
    return r


def setup_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="bbsmoke-"))
    (root / "programs").mkdir()
    shutil.copytree(REAL / "programs" / "_template", root / "programs" / "_template")
    shutil.copytree(REAL / "agents", root / "agents")
    shutil.copytree(REAL / "modes", root / "modes")
    (root / "lib").mkdir()
    shutil.copy2(REAL / "lib" / "skill_roots.json", root / "lib" / "skill_roots.json")
    shutil.copy2(REAL / "lib" / "state.py", root / "lib" / "state.py")
    (root / "scripts").mkdir()
    shutil.copy2(REAL / "scripts" / "skills_lookup.py", root / "scripts" / "skills_lookup.py")
    (root / "benchmark" / "runs").mkdir(parents=True)
    for p in (REAL / "benchmark" / "runs").glob("*.json"):
        shutil.copy2(p, root / "benchmark" / "runs" / p.name)
    (root / "skills").mkdir()
    (root / "findings").mkdir()
    (root / "labs" / "HTB" / "machines").mkdir(parents=True)
    return root


SCOPE_MD = """# Demo program

## In-scope assets

| Asset | Notes |
|---|---|
| `api.demo.test` | API |
| `*.app.demo.test` | web |
| `demo.test/v1/*` | versioned API |

## Exclusions

| Asset | Notes |
|---|---|
| `admin.demo.test` | out of scope |
"""

FINDING = {
    "id": "F-001", "program": "demo", "target": "https://api.demo.test/v1/users/2",
    "endpoint": "/v1/users/:id", "method": "GET", "vuln_class": "idor",
    "summary": "IDOR in /v1/users allows an authenticated attacker to read another tenant's private profile data",
    "impact": "An authenticated attacker can read another tenant's private profile data",
    "curl_poc": "curl -s 'https://api.demo.test/v1/users/2' -H 'Cookie: session=abc123'",
    "evidence": ["evidence/request.txt", "evidence/response.txt"],
    "control_evidence": "evidence/control.txt",
    "reproduced": True, "deterministic": True, "not_documented": True,
    "identity_proven": True, "unrealistic_preconditions": False,
    "chain_proven": False, "skill_checked": True,
    "already_tried": False, "cheaper_test": "",
    "confirm_refute": "attacker session gets 200 with victim data; control gets 403",
    "refute_plan": "record the dead end and test the graphql path next",
    "status": "scanner_hit",
}


def main() -> int:
    root = setup_root()
    try:
        print(f"[0] temp root {root}")

        run(root, "init", "demo", expect=0)
        ws = root / "programs" / "demo"
        (ws / "scope.md").write_text(SCOPE_MD)
        ws.mkdir(exist_ok=True)
        (ws / "evidence").mkdir(exist_ok=True)
        for n in ("request.txt", "response.txt", "control.txt"):
            (ws / "evidence" / n).write_text("captured\n")
        print("[1] init + scope.md")

        run(root, "scope-check", "api.demo.test", "--program", "demo", expect=0)
        run(root, "scope-check", "https://x.app.demo.test/a", "--program", "demo", expect=0)
        run(root, "scope-check", "admin.demo.test", "--program", "demo", expect=2)
        run(root, "scope-check", "evil.test", "--program", "demo", expect=2)
        r = run(root, "scope-check", "https://evil.test", "--program", "demo", "--json",
                expect=2)
        assert json.loads(r.stdout)["in_scope"] is False
        r = run(root, "scope-check", "--program", "demo", "--full", expect=0)
        assert "api.demo.test" in r.stdout and "admin.demo.test" in r.stdout
        print("[2] scope gate allow/deny + enumeration")

        run(root, "state", str(ws), "set-target", "--target", "https://api.demo.test",
            "--mode", "bugbounty", expect=0)
        run(root, "state", str(ws), "set-extra", "--key", "k", "--value", '{"a": 1}',
            expect=0)
        r = run(root, "state", str(ws), "get-extra", "--key", "k", expect=0)
        assert '"a": 1' in r.stdout
        run(root, "state", str(ws), "add-hyp", "--id", "h1",
            "--statement", "sudo SUID binary gives root", "--confidence", "0.8",
            "--cost", "1.0", expect=0)
        run(root, "next-hyp", "--workspace", str(ws), "--apply", expect=0)
        raw = json.loads((ws / "state.json").read_text())
        assert raw["hypotheses"]["h1"]["cost"] > 1.0, "prior cost was not applied"
        print("[3] state extensions + prior-adjusted cost apply")

        run(root, "leads", "add", "--workspace", str(ws), "--skill", "hunt-idor",
            "--evidence", "https://api.demo.test/v1/users/2?id=2", "--priority", "high",
            expect=0)
        r = run(root, "leads", "list", "--workspace", str(ws), "--json", expect=0)
        leads_list = json.loads(r.stdout)
        assert leads_list and leads_list[0]["skill"] == "hunt-idor"
        lid = leads_list[0]["id"]
        run(root, "leads", "claim", lid, "--workspace", str(ws), expect=0)
        r = run(root, "leads", "list", "--workspace", str(ws), "--json", expect=0)
        assert json.loads(r.stdout)[0]["status"] == "investigating"
        print("[4] lead board add/list/claim")

        (root / "findings").mkdir(exist_ok=True)
        fp = root / "findings" / "F-001.json"
        fp.write_text(json.dumps(FINDING))
        r = run(root, "validate", "F-001", "--workspace", str(ws), expect=0)
        assert "validated_finding" in r.stdout
        raw = json.loads((ws / "state.json").read_text())
        assert "validated-finding" in raw["milestones"]
        assert (root / "findings" / "F-001.validation.json").exists()
        print("[5] validate -> validated_finding + milestone")

        r = run(root, "report", "F-001", "--workspace", str(ws), expect=0)
        report_path = ws / "findings" / "F-001-report.md"
        assert report_path.exists()
        text = report_path.read_text()
        assert "redacted" in text.lower(), "cookie secret was not redacted"
        assert "evidence/response.txt" in text
        print("[6] report render + secret redaction")

        dup = dict(FINDING, id="F-002")
        (root / "findings" / "F-002.json").write_text(json.dumps(dup))
        r = run(root, "validate", "F-002", "--workspace", str(ws), expect=1)
        assert "gate4" in r.stdout.lower() or "duplicate" in r.stdout.lower()
        print("[7] duplicate rejected by gate 4")

        # learning loop: add a confirmed hypothesis and commit an approved skill
        run(root, "state", str(ws), "add-hyp", "--id", "h2",
            "--statement", "IDOR in /v1/users allows cross-tenant profile reads",
            "--evidence", "two-account comparison", "--confidence", "0.9",
            "--test", "swap id", expect=0)
        run(root, "state", str(ws), "update-hyp", "--id", "h2", "--status", "confirmed",
            "--result", "200 with victim data", expect=0)
        r = run(root, "learn", "--workspace", str(ws), "--json", expect=0)
        payload = json.loads(r.stdout)
        assert payload["candidates"], "no learn candidates generated"
        cid = payload["candidates"][0]["id"]
        run(root, "learn", "--workspace", str(ws), "--approve", cid, expect=0)
        r = run(root, "learn", "--workspace", str(ws), "--commit", expect=0)
        assert list((root / "skills").rglob("*.md")), "no skill committed"
        print("[8] learn candidates -> approve -> commit")

        # dry-run orchestrator + resume, on a separate HTB workspace
        drun = root / "labs" / "HTB" / "machines" / "dry"
        run(root, "run", "--mode", "htb", "--workspace", str(drun),
            "--target", "10.10.10.10", "--dry-run", "--max-rounds", "1", "--no-ui",
            expect=0)
        assert (drun / "agent_logs").is_dir()
        hb1 = json.loads((drun / "state.json").read_text())["bb_heartbeat"]
        assert hb1["rounds_completed"] == 1
        run(root, "run", "--mode", "htb", "--workspace", str(drun), "--resume",
            "--target", "10.10.10.10", "--dry-run", "--max-rounds", "2", "--no-ui",
            expect=0)
        hb2 = json.loads((drun / "state.json").read_text())["bb_heartbeat"]
        assert hb2["rounds_completed"] == 2, hb2
        print("[9] dry-run round-robin + resume heartbeat")

        run(root, "benchmark", "summary", expect=0)
        run(root, "benchmark", "priors", expect=0)
        assert (root / "lib" / "bb" / "priors.json").exists() or \
               (REAL / "lib" / "bb" / "priors.json").exists()
        run(root, "doctor", "--no-manifest", expect=0)
        run(root, "doctor", expect=0)
        assert (root / "MANIFEST.json").exists()
        print("[10] benchmark + doctor + MANIFEST")

        print("\nALL BB CHECKS PASSED")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        raise SystemExit(1)
