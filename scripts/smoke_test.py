#!/usr/bin/env python3
"""
End-to-end smoke test for the state/hypothesis engine, no LLM or network
involved. Run this FIRST, before burning any model calls on a real OpenCode
run — it proves lib/state.py works correctly on your actual machine (right
Python version, paths resolve, nothing environment-specific broke) and
gives you a worked example of the exact calls orchestrator.md/htb.md
describe in prose.

    python3 scripts/smoke_test.py

Exits 0 and prints "ALL CHECKS PASSED" on success, or raises an
AssertionError pointing at exactly what broke.
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.state import TargetState  # noqa: E402

WORKSPACE = Path(__file__).resolve().parent.parent / "labs" / "HTB" / "machines" / "_smoke_test"


def main():
    # clean slate
    if WORKSPACE.exists():
        shutil.rmtree(WORKSPACE)

    # --- 1. fresh state, mirrors what orchestrator.md step 3 does on startup ---
    state = TargetState.load(WORKSPACE, target="10.129.99.99", mode="htb")
    assert state.target == "10.129.99.99"
    assert state.next_hypothesis() is None, "fresh state should have no open hypotheses"
    print("[1/9] fresh state loads cleanly")

    # --- 2. hypothesis generation, mirrors htb.md step 3 ---
    state.add_hypothesis(
        "h1", "Apache Tomcat manager allows PUT upload",
        evidence="tomcat 8.5.19, /manager/html exposed, nmap scan",
        confidence=0.7, cost=1.0, test="PUT war via /manager/text/deploy",
    )
    state.add_hypothesis(
        "h2", "SMB null session readable share",
        evidence="smb open, no auth required per smbclient -L",
        confidence=0.4, cost=2.0, test="smbclient -N //target/share",
    )
    state.add_hypothesis(
        "h3", "Low-confidence guess worth almost nothing",
        evidence="pure speculation, no real evidence",
        confidence=0.1, cost=3.0, test="brute force everything",
    )
    nxt = state.next_hypothesis()
    assert nxt is not None and nxt.id == "h1", (
        f"expected h1 (score 0.7) to rank first, got {nxt.id if nxt else None} "
        "- the confidence/cost ranking is broken"
    )
    print(f"[2/9] hypothesis ranking correct: {nxt.id} picked first (score={nxt.score():.2f})")

    # --- 3. action dedup, mirrors the critic gate's question 3 ---
    cmd = "nmap -sV -p- 10.129.99.99"
    assert state.already_tried(cmd) is None, "nothing recorded yet, should be None"
    state.record_action(cmd, "tomcat 8.5.19 on 8080, smb open on 445")
    assert state.already_tried(cmd) is not None, "action should now be recorded"
    # near-duplicate (whitespace) must still dedupe - this is the actual
    # mechanism that stops an agent re-running a scan it already ran
    assert state.already_tried("nmap   -sV  -p-   10.129.99.99  ") is not None, (
        "whitespace-normalized dedup is broken - repeated scans won't be caught"
    )
    print("[3/9] action dedup works, including whitespace-normalized near-dupes")

    # --- 4. exploitation + result recording, mirrors htb.md step 4 ---
    state.update_hypothesis("h1", status="confirmed", result="shell as tomcat")
    assert state.hypotheses["h1"].status == "confirmed"
    nxt = state.next_hypothesis()
    assert nxt is not None and nxt.id == "h2", (
        f"h1 is confirmed and should drop out of ranking, expected h2 next, got {nxt.id if nxt else None}"
    )
    print(f"[4/9] confirmed hypothesis drops out of ranking, next up: {nxt.id}")

    # --- 5. failure memory, mirrors htb.md step 6 ---
    state.mark_failed("SMB null session read", "access denied - share requires auth")
    assert state.is_known_failed("smb null session read"), "case-insensitive match should work"
    assert not state.is_known_failed("completely unrelated technique")
    print("[5/9] failure memory records and matches correctly")

    # --- 6. milestones, mirrors htb.md step 7 / benchmark ---
    import time
    t1, fresh1 = state.mark_milestone("user")
    assert fresh1, "first mark should be recorded"
    time.sleep(0.01)
    t2, fresh2 = state.mark_milestone("root")
    assert fresh2
    assert t2 > t1 >= 0, "milestones should be monotonically increasing elapsed-time floats"
    # keep-first: a re-mark must not reset the clock (accidental repeats)
    t1_again, fresh_again = state.mark_milestone("user")
    assert not fresh_again and t1_again == t1, "re-marking a milestone must be a no-op"
    # --at backfill: absolute epoch, converted to elapsed-since-start
    t3, fresh3 = state.mark_milestone("flag", at=time.time() + 60)
    assert fresh3 and t3 > t2, "backfilled milestone should convert --at to elapsed time"
    print(f"[6/9] milestones keep-first + --at backfill: user={t1:.4f}s, root={t2:.4f}s, flag={t3:.1f}s")

    # --- 7. persistence round-trip, mirrors orchestrator.md step 7 (save every iteration) ---
    state.save()
    assert WORKSPACE.joinpath("state.json").exists(), "state.json should exist on disk"
    reloaded = TargetState.load(WORKSPACE)
    assert reloaded.hypotheses["h1"].status == "confirmed", "persisted state should survive reload"
    assert reloaded.already_tried(cmd) is not None, "actions should survive reload"
    assert reloaded.milestones.get("root") == t2, "milestones should survive reload"
    # unknown top-level keys (hand-added run metadata, e.g. Bedside-style
    # status/flags/completed_at) must survive a mutation+save round-trip
    import json
    raw = json.loads(WORKSPACE.joinpath("state.json").read_text())
    raw["status"] = "owned"
    raw["flags"] = {"user": "aaa", "root": "bbb"}
    WORKSPACE.joinpath("state.json").write_text(json.dumps(raw))
    with_extras = TargetState.load(WORKSPACE)
    with_extras.record_action("extra-key check", "noop")
    with_extras.save()
    raw2 = json.loads(WORKSPACE.joinpath("state.json").read_text())
    assert raw2.get("status") == "owned", "unknown top-level keys must survive save()"
    assert raw2.get("flags", {}).get("root") == "bbb", "nested unknown keys must survive verbatim"
    print("[7/9] state persists and reloads correctly (unknown keys preserved)")

    # --- 8. mailbox, mirrors the multi-agent handoff protocol in agents/*.md ---
    reloaded.post_message("recon-agent", "web-agent", "tomcat 8.5.19 on :8080", "finding")
    reloaded.post_message("recon-agent", "all", "smb open on 445", "info")
    web_inbox = reloaded.inbox("web-agent")
    assert len(web_inbox) == 2, "web-agent should see both its direct message and the broadcast"
    ad_inbox = reloaded.inbox("ad-agent")
    assert len(ad_inbox) == 1, "ad-agent should see only the broadcast, not web-agent's direct message"
    assert ad_inbox[0].text == "smb open on 445"
    reloaded.mark_read("web-agent", [web_inbox[0].id])
    web_unread = reloaded.inbox("web-agent")
    assert len(web_unread) == 1, "marking one message read should leave the other unread"
    reloaded.save()
    reloaded2 = TargetState.load(WORKSPACE)
    assert len(reloaded2.messages) == 2, "messages should survive reload"
    assert "web-agent" in reloaded2.messages[0].read_by, "read-receipts should survive reload"
    print("[8/9] mailbox routes direct/broadcast messages and persists read-state correctly")

    # --- 9. benchmark summary, mirrors orchestrator.md "on completion" step ---
    summary = reloaded2.benchmark_summary()
    # event log keeps the extra action even though the later stale
    # snapshot was written from an older instance
    assert summary["unique_actions"] == 2
    assert summary["hypotheses_total"] == 3
    assert summary["hypotheses_confirmed"] == 1
    assert summary["dead_ends"] == 1
    assert summary["time_to_root_s"] == t2
    print(f"[9/9] benchmark summary correct: {summary}")

    shutil.rmtree(WORKSPACE)
    print("\nALL CHECKS PASSED - lib/state.py works correctly on this machine.")
    print("Next: spawn a real HTB target and point OpenCode at agents/orchestrator.md")
    print("(or scripts/multi_agent_run.py for the multi-specialist mailbox loop).")


if __name__ == "__main__":
    main()
