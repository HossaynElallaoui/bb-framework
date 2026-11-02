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
    shutil.copytree(REAL / "lib" / "bb", root / "lib" / "bb")
    (root / "scripts").mkdir()
    shutil.copy2(REAL / "scripts" / "skills_lookup.py", root / "scripts" / "skills_lookup.py")
    (root / "benchmark" / "runs").mkdir(parents=True)
    for p in (REAL / "benchmark" / "runs").glob("*.json"):
        shutil.copy2(p, root / "benchmark" / "runs" / p.name)
    (root / "skills").mkdir()
    (root / "findings").mkdir()
    (root / "labs" / "HTB" / "machines").mkdir(parents=True)
    (root / "composites").mkdir()
    for name in ("web-recon.sh", "ad-enum.sh", "lin-privesc.sh"):
        shutil.copy2(REAL / "composites" / name, root / "composites" / name)
    shutil.copy2(REAL / "composites" / "manifest.json",
                 root / "composites" / "manifest.json")
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

        # §3.5 synchronous validation: confirm -> skeleton + auto-gates
        run(root, "state", str(ws), "add-hyp", "--id", "h3",
            "--statement", "idor in /v1/users", "--confidence", "0.8", expect=0)
        run(root, "state", str(ws), "update-hyp", "--id", "h3",
            "--status", "confirmed", "--result", "200 with victim data", expect=0)
        skel = ws / "findings" / "h3.json"
        assert skel.exists(), "auto finding skeleton not created"
        assert json.loads(skel.read_text())["status"] == "confirmed_unvalidated"
        raw = json.loads((ws / "state.json").read_text())
        lv = raw.get("bb_last_validation") or {}
        assert lv.get("hypothesis_id") == "h3" and lv.get("failed_gates"), lv
        assert any("h3 confirmed" in m.get("text", "") for m in raw.get("messages", []))
        print("[7b] confirm -> finding skeleton + auto-gates + mailbox")

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

        # regression gate: pin -> self-compare pass -> regressed run fails
        run(root, "benchmark", "pin", "--machine", "Connected", expect=0)
        assert (root / "benchmark" / "baselines" / "connected.json").exists()
        gold = root / "benchmark" / "runs" / "Connected-1792265326.json"
        if not gold.exists():
            gold = next((root / "benchmark" / "runs").glob("Connected-*.json"))
        run(root, "benchmark", "gate", "--machine", "Connected",
            "--snapshot", str(gold), expect=0)
        bad = root / "benchmark" / "runs" / "Connected-9999999999.json"
        bad.write_text(json.dumps({
            "machine": "Connected", "unique_actions": 30, "dead_ends": 3,
            "time_to_root_s": 800.0, "hypotheses_confirmed": 2}))
        run(root, "benchmark", "gate", "--machine", "Connected",
            "--snapshot", str(bad), expect=1)
        run(root, "benchmark", "gate", "--machine", "Nosuch",
            "--snapshot", str(bad), expect=2)
        # live plumbing (offline): dry-run gate produces no root -> regress
        run(root, "benchmark", "gate", "--machine", "Connected", "--run",
            "--dry-run", "--target", "10.10.10.10", "--no-ui", expect=1)
        print("[11] regression gate pin/pass/regress/no-baseline/dry-run")

        # similar-box fingerprints: synthetic solved box -> index -> similar
        fws = root / "labs" / "HTB" / "machines" / "Goldbox"
        fws.mkdir(parents=True)
        (fws / "nmap_svc.txt").write_text(
            "PORT     STATE SERVICE VERSION\n"
            "22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)\n"
            "443/tcp  open  ssl/https Apache/2.4.6 (CentOS) PHP/7.4.16\n")
        gold_state = {
            "target": "10.10.10.1", "mode": "htb", "started_at": 0.0,
            "actions": {"a": {"key": "a", "command": "nmap -sV", "result_summary": "x",
                              "timestamp": 0.0}},
            "hypotheses": {"h1": {"id": "h1", "statement": "web app SQLi gives admin",
                                  "evidence": "e", "confidence": 0.9, "cost": 2.0,
                                  "test": "probe", "status": "confirmed",
                                  "result": "r", "created_at": 0.0,
                                  "updated_at": 0.0},
                           "h2": {"id": "h2", "statement": "SQLi in the product page dumps the database",
                                  "evidence": "", "confidence": 0.5, "cost": 1.0,
                                  "test": "probe", "status": "open",
                                  "result": "", "created_at": 0.0,
                                  "updated_at": 0.0}},
            "failed_paths": [], "milestones": {"root": 100.0, "flag": 101.0},
            "messages": [], "extra": {}}
        (fws / "state.json").write_text(json.dumps(gold_state))
        run(root, "fingerprints", "rebuild", expect=0)
        r = run(root, "similar", "--workspace", str(fws), "--json", expect=0)
        sim = json.loads(r.stdout)
        assert sim["hits"] and sim["hits"][0]["machine"] == "Goldbox", sim
        assert "exploit" in sim["category_bias"], sim
        r = run(root, "next-hyp", "--workspace", str(fws), "--json", expect=0)
        rows = json.loads(r.stdout)
        assert rows and rows[0].get("sim_hint"), rows
        print("[12] fingerprint index + similar + next-hyp bias")

        run(root, "composite", "list", expect=0)
        r = run(root, "composite", "show", "web-recon", "--json", expect=0)
        assert json.loads(r.stdout)["script"] == "web-recon.sh"
        run(root, "composite", "show", "nosuch", expect=2)
        print("[13] composite bundles list/show")

        # §3.1 asset diffing: pure logic offline + CLI surface
        sys.path.insert(0, str(REAL))
        from lib.bb import assets as bb_assets
        assert bb_assets.norm_host("Example.COM.") == "example.com"
        assert bb_assets.norm_url("https://api.demo.test/v1/users/?x=1") == \
            "https://api.demo.test/v1/users"
        d = bb_assets.diff_records({"a": 1, "b": 2}, {"b": 2, "c": 3})
        assert d == {"added": ["c"], "gone": ["a"], "unchanged": ["b"]}, d
        run(root, "assets", "show", "--workspace", str(ws), expect=0)
        print("[14] asset diffing pure logic + CLI")

        # §1.2 second-opinion pass: verdict parsing + deterministic kickback
        from lib.bb import verify as bb_verify
        assert bb_verify.parse_verdict("VERDICT: AGREE")[0] == "agree"
        assert bb_verify.parse_verdict(
            "VERDICT: KICKBACK — no control result shown")[0] == "kickback"
        assert bb_verify.parse_verdict("looks fine to me")[0] == "unclear"
        run(root, "state", str(ws), "add-hyp", "--id", "h9",
            "--statement", "idor check", "--confidence", "0.9", expect=0)
        run(root, "state", str(ws), "update-hyp", "--id", "h9",
            "--status", "confirmed", "--result", "200", expect=0)
        assert bb_verify.apply_kickback(ws, "h9", "no control shown", "web-agent")
        raw = json.loads((ws / "state.json").read_text())
        assert raw["hypotheses"]["h9"]["status"] == "open"
        assert raw["bb_verifications"][0]["verdict"] == "kickback"
        assert not bb_verify.apply_kickback(ws, "h9", "again", "web-agent")
        run(root, "run", "--mode", "htb", "--workspace", str(drun),
            "--target", "10.10.10.10", "--dry-run", "--max-rounds", "1",
            "--no-ui", "--no-verify", expect=0)
        print("[15] verify pass: parse/kickback/no-verify flag")

        # §1.5 typed mailbox, §1.7 coverage, §1.1 router, §2.3 refit
        run(root, "state", str(ws), "post-msg", "--from", "web-agent",
            "--to", "critic-agent", "--type", "finding", "--hyp-id", "h2",
            "--payload", '{"port": 443}', "--text", "finding on h2", expect=0)
        r = run(root, "state", str(ws), "inbox", "--for", "critic-agent",
                "--type", "finding", "--hyp-id", "h2", expect=0)
        assert "finding:h2" in r.stdout
        run(root, "coverage", "--workspace", str(ws), expect=0)
        run(root, "router", "status", expect=0)
        run(root, "benchmark", "priors", "--refit", expect=0)
        print("[16] typed mailbox / coverage / router / priors refit")

        # §2.4 diagnosis, §3.2 payouts, §3.3 dupecheck, §3.4 redaction, §3.6 claimant
        sys.path.insert(0, str(REAL))
        from lib.bb import diagnose as bb_diag
        d = bb_diag.diagnose(ws, "web-agent")
        assert isinstance(d.get("diagnosis"), str)
        (ws / "payouts.json").write_text(json.dumps({"exploit": 2000}))
        run(root, "next-hyp", "--workspace", str(ws), expect=0)
        (ws / "known-issues.md").write_text(
            "# known issues\n- idor in /v1/users already reported by X\n")
        r = run(root, "dupecheck", "F-001", "--workspace", str(ws), expect=1)
        assert "known-issues" in r.stdout.lower()
        from lib.bb import learn as bb_learn
        body, n = bb_learn.redact_body(
            "scan api.demo.test as admin@demo.test tok=abcdef123456789012345678",
            ws, "bugbounty")
        assert "api.demo.test" not in body and "<target>" in body and n >= 2, body
        body_htb, n0 = bb_learn.redact_body("scan api.demo.test", ws, "htb")
        assert n0 == 0 and "api.demo.test" in body_htb
        run(root, "leads", "claim", lid, "--workspace", str(ws),
            "--claimant", "operator", expect=0)
        r = run(root, "leads", "list", "--workspace", str(ws), "--json", expect=0)
        assert json.loads(r.stdout)[0].get("claimant") == "operator"
        print("[17] diagnose / payouts / dupecheck / redaction / claimant")

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
