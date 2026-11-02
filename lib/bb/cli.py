"""`bb` command surface.

One deterministic entrypoint wrapping the proven engine. Every subcommand is
either a thin wrapper over lib/state.py, a deterministic port of upstream
tooling, or presentation. No subcommand calls a model.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from lib.bb import __version__, benchmark, config, doctor, learn, leads, priors, report
from lib.bb import gate, regression, runner, scope, statex, ui, validate
from lib.bb import assets, fingerprint
from lib.state import TargetState

AGENT_CHOICES = ["all", *config.ALL_AGENTS]


def _base(args) -> Path:
    if getattr(args, "root", None):
        b = Path(args.root).expanduser().resolve()
        os.environ["BB_ROOT"] = str(b)
        return b
    return config.root()


def _ws(args, base: Path, required: bool = True) -> Path | None:
    spec = getattr(args, "workspace", None)
    ws = config.resolve_workspace(spec, base)
    if ws is None and required:
        print("error: --workspace is required (or a workspace path as the first arg)",
              file=sys.stderr)
    return ws


def _slug_ok(slug: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug))


# ---- init ---------------------------------------------------------------

def cmd_init(args) -> int:
    base = _base(args)
    slug = args.program
    if not _slug_ok(slug):
        print("error: program slug must be lowercase letters/numbers with single hyphens",
              file=sys.stderr)
        return 2
    dest = base / "programs" / slug
    if dest.exists():
        print(f"error: workspace already exists: {dest}", file=sys.stderr)
        return 2
    template = base / "programs" / "_template"
    if not template.exists():
        print(f"error: missing template: {template}", file=sys.stderr)
        return 2
    shutil.copytree(template, dest)
    env = dest / "scope.env"
    if not env.exists():
        env.write_text(
            "# Hard scope config consumed by `bb scope-check`.\n"
            "# Restrict the markdown parser's allow list, or widen it deliberately.\n"
            "BB_ALLOW=\n"
            "BB_EXCLUDE=\n"
            "BB_EXCLUDED_CLASSES=\n"
            "# BB_RATE_PER_MIN=12\n"
            "# BB_REQUIRED_HEADER=User-Agent: Program-Identifier\n"
            "# BB_MAX_CONCURRENCY=1\n")
    print(f"created {dest}")
    burp = doctor.check_root_owned_burp(base)
    if burp["status"] == "warn":
        print(f"note: {burp['detail']}")
        print("      review with `bb doctor` (root-owned data is never deleted silently)")
    print(f"next: fill in {dest / 'scope.md'} (in-scope assets + exclusions), then:")
    print(f"  bb scope-check --program {slug} --full")
    print(f"  bb run --mode bounty --workspace {dest} --target <first-host>")
    return 0


# ---- scope --------------------------------------------------------------

def cmd_scope_check(args) -> int:
    base = _base(args)
    program = args.program or (Path(args.workspace).name if args.workspace else None)
    ws = config.resolve_workspace(args.workspace, base) if args.workspace else None

    if args.full:
        pol = scope.load_policy(program=program, workspace=ws, mode=args.mode, base=base)
        if pol is None:
            print("DENY: no scope policy found (fail closed)", file=sys.stderr)
            return 2
        data = scope.enumerate_policy(pol)
        if not data["allow"]:
            print("DENY: policy has no in-scope allow patterns — fill in scope.md "
                  "(failing closed)", file=sys.stderr)
            if args.json:
                ui.json_out(data)
            return 2
        if args.json:
            ui.json_out(data)
        else:
            ui.kv_table(f"scope policy — {data['program']}", {
                "mode": data["mode"], "allow": "\n".join(data["allow"]) or "(none)",
                "exclude": "\n".join(data["exclude"]) or "(none)",
                "excluded classes": ", ".join(data["excluded_classes"]) or "(none)",
                "rate/min": data["rate_per_min"], "required header": data["required_header"],
                "max concurrency": data["max_concurrency"],
                "sources": ", ".join(data["sources"]) or "(none)", "note": data["note"],
            })
        return 0

    if args.file:
        pol = scope.load_policy(program=program, workspace=ws, mode=args.mode, base=base)
        if pol is None:
            print("DENY: no scope policy found (fail closed)", file=sys.stderr)
            return 2
        urls = [l.strip() for l in Path(args.file).read_text().splitlines() if l.strip()]
        inside = [u for u in urls if pol.check(u)["in_scope"]]
        outside = [u for u in urls if not pol.check(u)["in_scope"]]
        if args.json:
            ui.json_out({"in_scope": inside, "out_of_scope": outside})
        else:
            print(f"{len(inside)} in scope, {len(outside)} out of scope")
            for u in outside[:20]:
                print(f"  DENY {u}")
        return 0 if not outside else 2

    if not args.target:
        print("error: provide a target, --file, or --full", file=sys.stderr)
        return 2
    ok, verdict = scope.check_target(args.target, program=program, workspace=ws,
                                     mode=args.mode, base=base)
    if args.json:
        ui.json_out(verdict)
    else:
        print(f"{'ALLOW' if ok else 'DENY'}: {args.target}")
        print(f"  reason: {verdict.get('reason')}")
        if verdict.get("matched_rule"):
            print(f"  rule:   {verdict['matched_rule']}")
        if verdict.get("sources"):
            print(f"  source: {', '.join(verdict['sources'])}")
    return 0 if ok else 2


def _resolve_machine_ip(machine: str, target: str | None) -> str | None:
    if target:
        return target
    for name in (f"{machine.lower()}.htb", machine):
        try:
            return socket.gethostbyname(name)
        except OSError:
            continue
    return None


def cmd_scope_sync(args) -> int:
    """Operator-confirmed HTB scope refresh: old IP -> current IP.

    Never used by `bb run` automatically. The gate stays fail-closed until
    a human (or explicit --yes) accepts the diff.
    """
    base = _base(args)
    machine = args.machine
    path = base / "programs" / "htb" / f"{machine.lower()}.json"
    if not path.exists():
        matches = [p for p in (base / "programs" / "htb").glob("*.json")
                   if p.stem.lower() == machine.lower()]
        if not matches:
            print(f"error: no HTB scope file for {machine!r} "
                  f"(expected {path})", file=sys.stderr)
            return 2
        path = matches[0]
    data = json.loads(path.read_text())
    hosts = list(((data.get("scope") or {}).get("hosts") or []))
    all_ips = [h for h in hosts if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h)]
    declared = data.get("target")
    old_ips = ([declared] if isinstance(declared, str)
               and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", declared)
               else all_ips)
    current = _resolve_machine_ip(machine, args.target)
    if not current:
        print(f"error: could not resolve current IP for {machine} "
              f"(pass --target <ip>)", file=sys.stderr)
        return 2
    if current in hosts:
        print(f"scope already current: {machine} -> {current}")
        return 0
    proposed = [h for h in hosts if h not in old_ips]
    proposed.insert(0, current)
    print(f"scope sync — {machine}")
    print(f"  file:    {config.rel(path, base)}")
    print(f"  declared:{(' ' + declared) if declared else ' (none)'}")
    print(f"  old IPs: {', '.join(old_ips) or '(none)'}")
    print(f"  current: {current}")
    print(f"  hosts:   {', '.join(proposed)}")
    if not args.yes:
        if not sys.stdin.isatty():
            print("dry-run only (pass --yes to apply)", file=sys.stderr)
            return 1
        answer = input("apply this scope change? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("not applied")
            return 1
    data["target"] = current
    data.setdefault("scope", {})["hosts"] = proposed
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)
    print(f"updated {config.rel(path, base)}")

    # Keep the matching workspace's state target aligned, but only after the
    # scope file itself has been accepted.
    for ws in config.discover_workspaces(base):
        if ws.name.lower() != machine.lower():
            continue
        statex.locked_update(ws, lambda s: setattr(s, "target", current))
        print(f"updated {config.rel(ws / 'state.json', base)} target -> {current}")
    return 0


# ---- run ----------------------------------------------------------------

def _htb_target_for(base: Path, machine: str | None) -> str | None:
    if not machine:
        return None
    p = base / "programs" / "htb" / f"{machine.lower()}.json"
    data = config.read_json(p, default={}) or {}
    return data.get("target")


def cmd_run(args) -> int:
    base = _base(args)
    resume_value = args.resume
    resume = resume_value is not None
    workspace = args.workspace
    if resume and resume_value:
        workspace = resume_value
    target = args.target
    machine = args.machine
    if not target:
        if workspace:
            ws = config.resolve_workspace(workspace, base)
            if ws:
                st = TargetState.load(ws)
                target = st.target or None
                machine = machine or ws.name
        if not target and args.mode == "htb" and machine:
            hint = base / "labs" / "HTB" / "machines" / machine
            if (hint / "state.json").exists():
                target = TargetState.load(hint).target or None
        if not target and args.mode == "htb":
            target = _htb_target_for(base, machine)
    unknown = [a for a in (args.agents or [])
               if not (base / "agents" / f"{a}.md").exists()]
    if unknown:
        print(f"error: unknown agent(s): {', '.join(unknown)}; "
              f"choose from {', '.join(config.ALL_AGENTS)}", file=sys.stderr)
        return 2
    if args.max_rounds < 1 or args.timeout < 1 or (args.parallel is not None and args.parallel < 1):
        print("error: --max-rounds/--timeout must be >=1 and --parallel >=1", file=sys.stderr)
        return 2
    if args.mode in ("bounty", "bugbounty") and not workspace and not args.program:
        print("error: bounty mode requires --workspace programs/<slug> or --program <slug> "
              "(scope must be loaded before any dispatch)", file=sys.stderr)
        return 2
    if not target:
        # derive from HTB scope json when machine name is enough
        print("error: --target is required (or seed state.json / pass --machine for HTB)",
              file=sys.stderr)
        return 2
    opts = runner.RunOptions(
        workspace=Path(workspace) if workspace else None,
        target=target, machine=machine, program=args.program, mode=args.mode,
        model=args.model, max_rounds=args.max_rounds, parallel=args.parallel,
        max_workers=args.max_workers,
        agents=args.agents or list(config.ROLE_SPECIALISTS),
        timeout=args.timeout, no_ui=args.no_ui, dry_run=args.dry_run,
        verify_confirms=not args.no_verify,
        resume=resume, base=base,
    )
    return runner.run(opts)


# ---- leads --------------------------------------------------------------

def _print_leads(rows: list[dict]) -> None:
    if not rows:
        ui.log("bb", "no leads")
        return
    table_rows = []
    for l in sorted(rows, key=leads.rank_key):
        table_rows.append([l.get("id"), l.get("status"), l.get("priority"),
                           l.get("skill"), (l.get("evidence") or "")[:70],
                           l.get("finding_id") or ""])
    ui.table("lead board", ["id", "status", "prio", "skill", "evidence", "finding"],
             table_rows)


def cmd_leads(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    sub = args.leads_cmd or "list"
    if sub == "ingest":
        if not args.recon_dir:
            print("error: --recon-dir required", file=sys.stderr)
            return 2
        res = leads.ingest(ws, Path(args.recon_dir))
        if args.json:
            ui.json_out(res)
        else:
            print(f"+{res['added']} new, {res['updated']} re-seen, "
                  f"{res['rejected']} rejected (total {res['total']})")
        return 0
    if sub == "next":
        l = leads.next_lead(ws)
        if not l:
            print("no untouched leads")
            return 0
        if args.json:
            ui.json_out(l)
        else:
            print(f"NEXT: {l['id']} [{l['priority']}] {l['skill']}")
            print(f"  evidence: {l['evidence']}")
            print(f"  why: {l['signal']} — {l['why']}")
        return 0
    if sub == "claim":
        l = leads.claim(ws, args.lead_id, note=args.note)
        if not l:
            print(f"lead not found: {args.lead_id}", file=sys.stderr)
            return 1
        print(f"claimed {l['id']} -> {l['status']}")
        return 0
    if sub == "touch":
        if args.status and args.status not in leads.STATUSES:
            print(f"invalid status; use {', '.join(leads.STATUSES)}", file=sys.stderr)
            return 2
        l = leads.touch(ws, args.lead_id, status=args.status, note=args.note,
                        finding_id=args.finding_id)
        if not l:
            print(f"lead not found: {args.lead_id}", file=sys.stderr)
            return 1
        print(f"{l['id']} -> {l.get('status')}")
        return 0
    if sub == "add":
        if not args.skill or not args.evidence:
            print("error: --skill and --evidence required", file=sys.stderr)
            return 2
        l = leads.add(ws, args.skill, args.evidence, signal=args.signal or "",
                      priority=args.priority, finding_id=args.finding_id)
        if not l:
            print("lead rejected or duplicate", file=sys.stderr)
            return 1
        print(f"added {l['id']} {l['skill']} {l['evidence']}")
        return 0

    rows = leads.load(ws)
    if args.status:
        rows = [l for l in rows if l.get("status") == args.status]
    if args.json:
        ui.json_out(rows)
    else:
        counts = leads.counts(ws)
        print(f"lead board: {config.rel(ws, base)} — "
              + ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())))
        _print_leads(rows)
    return 0


# ---- deterministic critic gate -----------------------------------------

def cmd_gate(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    verdict = gate.evaluate(
        workspace=ws, target=args.target or "", cmd=args.cmd or "",
        method=args.method or "", mode=args.mode,
        skill_checked=args.skill_checked, keywords=args.keywords or "",
        trivial=args.trivial, force=args.force,
        allow_unsafe=args.allow_unsafe, base=base)
    try:
        statex.record_gate(ws, verdict.allow, command=args.cmd or "",
                           agent=getattr(args, "agent", "") or "",
                           reason="; ".join(verdict.reasons))
    except Exception:
        pass
    if args.json:
        ui.json_out({"allow": verdict.allow, "reasons": verdict.reasons,
                     "checks": verdict.checks})
    else:
        print(verdict.render())
    return 0 if verdict.allow else 2


# ---- validate / report --------------------------------------------------

def _resolve_finding(args, base: Path, ws: Path | None) -> Path | None:
    if getattr(args, "file", None):
        p = Path(args.file)
        return p if p.is_absolute() else (base / p)
    fid = args.finding_id
    if not fid:
        print("error: finding id or --file required", file=sys.stderr)
        return None
    p = validate.find_finding(fid, ws, base)
    if not p:
        print(f"finding not found: {fid} (looked in workspace/findings, findings/, "
              f"programs/*/findings)", file=sys.stderr)
    return p


def cmd_validate(args) -> int:
    base = _base(args)
    ws = _ws(args, base, required=False)
    p = _resolve_finding(args, base, ws)
    if not p or not p.exists():
        return 2
    f = validate.load_finding(p)
    if getattr(args, "mode", None):
        f["mode"] = args.mode
    if not ws and f.get("workspace"):
        ws = config.resolve_workspace(f["workspace"], base)
    if not ws:
        # infer from programs/<slug>/findings path
        for parent in p.parents:
            if (parent / "state.json").exists():
                ws = parent
                break
    payload = validate.validate(f, workspace=ws, base=base, write=not args.no_write)
    if args.json:
        ui.json_out(payload)
    else:
        ok = payload["status"] == "validated_finding"
        ui.log("bb", f"{payload['finding_id']}: {payload['status']}",
               "info" if ok else "error")
        rows = [[f"gate{g['n']}", g["name"], "PASS" if g["pass"] else "FAIL",
                 g["notes"].get("reason", "")] for g in payload["gates"]]
        ui.table("4 gates", ["gate", "name", "result", "reason"], rows)
        qrows = [[f"Q{q['n']}", q["question"], "PASS" if q["pass"] else "FAIL",
                  q.get("detail", "")] for q in payload["questions"]]
        ui.table("7-question critic gate", ["q", "question", "result", "detail"], qrows)
        if payload.get("rejection_reasons"):
            ui.panel("rejected", "\n".join(f"- {r}" for r in payload["rejection_reasons"]),
                     style="red")
    return 0 if payload["status"] == "validated_finding" else 1


def cmd_report(args) -> int:
    base = _base(args)
    ws = _ws(args, base, required=False)
    p = _resolve_finding(args, base, ws)
    if not p or not p.exists():
        return 2
    f = validate.load_finding(p)
    if getattr(args, "mode", None):
        f["mode"] = args.mode
    if not ws and f.get("workspace"):
        ws = config.resolve_workspace(f["workspace"], base)
    path, redacted = report.write_report(f, out=args.out, workspace=ws, base=base)
    print(f"report: {config.rel(path, base)}")
    if redacted:
        print("note: secret-looking values were redacted; raw request stays in the evidence path.")
    return 0


# ---- skills -------------------------------------------------------------

def _skills_module(base: Path):
    real_scripts = Path(__file__).resolve().parents[2] / "scripts"
    for d in (base / "scripts", real_scripts):
        if (d / "skills_lookup.py").exists():
            if str(d) not in sys.path:
                sys.path.insert(0, str(d))
    import skills_lookup  # type: ignore
    return skills_lookup


def cmd_skills(args) -> int:
    base = _base(args)
    mod = _skills_module(base)
    if args.prewarm:
        n = mod.prewarm()
        print(f"skills index warmed: {n} entries")
        return 0
    if args.audit:
        clusters = mod.audit()
        if args.json:
            ui.json_out(clusters)
        else:
            rows = [[c["similarity"], c["a"], c["b"]] for c in clusters[:args.limit]]
            ui.table("near-duplicate skill clusters (manual merge decision)",
                     ["similarity", "a", "b"], rows)
            print(f"{len(clusters)} candidate pairs — nothing was deleted.")
        return 0
    query = " ".join(args.query)
    if not query:
        print("error: provide keywords, --audit, or --prewarm", file=sys.stderr)
        return 2
    results = mod.search(query, limit=args.limit)
    if args.json:
        ui.json_out([{k: v for k, v in r.items() if k != "tokens"} for r in results])
        return 0
    if not results:
        print("(no matching skills found — try broader keywords)")
        return 0
    rows = [[r["kind"], r["path"], (r.get("snippet") or "")[:100]] for r in results]
    ui.table(f"skills matching: {query}", ["kind", "path", "snippet"], rows)
    return 0


# ---- learn --------------------------------------------------------------

def cmd_learn(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    if args.approve:
        hit = learn.approve(ws, args.approve, value=not args.reject)
        if not hit:
            print(f"candidate not found: {args.approve}", file=sys.stderr)
            return 1
        print(f"{hit['id']} approved={hit['approved']}")
        return 0
    if args.show:
        data = learn.load(ws)
        hit = next((c for c in data.get("candidates", []) if c.get("id") == args.show), None)
        if not hit:
            print(f"candidate not found: {args.show}", file=sys.stderr)
            return 1
        print(hit.get("body", ""))
        return 0
    if args.edit:
        data = learn.load(ws)
        hit = next((c for c in data.get("candidates", []) if c.get("id") == args.edit), None)
        if not hit:
            print(f"candidate not found: {args.edit}", file=sys.stderr)
            return 1
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
        if not editor:
            print(f"set $EDITOR to edit; current body:\n{hit.get('body','')}")
            return 0
        import tempfile
        with tempfile.NamedTemporaryFile("w+", suffix=".md", delete=False) as tf:
            tf.write(hit.get("body", ""))
            tmp = tf.name
        rc = subprocess.call([editor, tmp])
        if rc == 0:
            learn.update_body(ws, args.edit, Path(tmp).read_text())
            print(f"updated {args.edit}")
        os.unlink(tmp)
        return 0 if rc == 0 else 1
    if args.commit:
        res = learn.commit(ws, base)
        print(f"committed {len(res['written'])}, skipped {len(res['skipped'])}")
        for p in res["written"]:
            print(f"  + {p}")
        for p in res["skipped"]:
            print(f"  = {p} (exists)")
        return 0
    payload = learn.generate(ws, base) if not args.no_generate else learn.load(ws)
    if args.json:
        ui.json_out(payload)
        return 0
    cands = payload.get("candidates", [])
    rows = [[c["id"], c["kind"], c["category"], c["name"],
             "yes" if c.get("approved") else "", "yes" if c.get("committed") else ""]
            for c in cands]
    ui.table(f"learn candidates — {config.rel(ws, base)}",
             ["id", "kind", "category", "name", "approved", "committed"], rows)
    print("approve: bb learn --workspace <ws> --approve <id>   commit: --commit")
    return 0


# ---- benchmark / regression gate ---------------------------------------

def _tolerances_from_args(args) -> dict | None:
    if not any((args.actions_pct, args.deadends_abs, args.deadends_pct,
                args.time_pct, args.confirmed_abs)):
        return None
    tol = json.loads(json.dumps(regression.DEFAULT_TOLERANCES))  # deep copy
    if args.actions_pct is not None:
        tol["unique_actions"]["pct"] = args.actions_pct
    if args.deadends_abs is not None:
        tol["dead_ends"]["abs"] = args.deadends_abs
    if args.deadends_pct is not None:
        tol["dead_ends"]["pct"] = args.deadends_pct
    if args.time_pct is not None:
        for k in ("time_to_user_s", "time_to_root_s", "time_to_flag_s"):
            tol[k]["pct"] = args.time_pct
    if args.confirmed_abs is not None:
        tol["hypotheses_confirmed"]["abs"] = args.confirmed_abs
    return tol


def cmd_benchmark_pin(args) -> int:
    base = _base(args)
    run_file = Path(args.run_from) if args.run_from else regression.pick_best_run(
        args.machine, base)
    if not run_file or not run_file.exists():
        print(f"error: no saved run found for machine {args.machine!r} — "
              f"pass --from <benchmark/runs/<file>.json>", file=sys.stderr)
        return 2
    data = regression.pin_baseline(args.machine, run_file, base,
                                   tolerances=_tolerances_from_args(args),
                                   notes=args.notes or "")
    if args.json:
        ui.json_out(data)
    else:
        ui.kv_table(f"baseline pinned — {data['machine']}", {
            "pinned from": data["pinned_from"],
            **{k: v for k, v in data["metrics"].items()},
            "baseline file": config.rel(regression.baseline_path(
                args.machine, base), base),
        })
    return 0


def cmd_benchmark_gate(args) -> int:
    base = _base(args)
    if args.run:
        try:
            payload, _ = regression.run_gate(
                args.machine, base, target=args.target, model=args.model,
                max_rounds=args.max_rounds, max_minutes=args.max_minutes,
                dry_run=args.dry_run, keep=args.keep, no_ui=args.no_ui)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    else:
        baseline = regression.load_baseline(args.machine, base)
        if not baseline:
            print(f"error: no baseline pinned for {args.machine!r} — "
                  f"`bb benchmark pin --machine {args.machine}` first",
                  file=sys.stderr)
            return 2
        snap = Path(args.snapshot) if args.snapshot else \
            regression.pick_latest_run(args.machine, base)
        if not snap or not snap.exists():
            print(f"error: no snapshot to compare — pass --snapshot "
                  f"<benchmark/runs/<file>.json> or use --run", file=sys.stderr)
            return 2
        payload = regression.compare(baseline, benchmark.load_run(snap))
        payload["machine"] = args.machine
        payload["baseline_file"] = config.rel(
            regression.baseline_path(args.machine, base), base)
        payload["snapshot_file"] = config.rel(snap, base)
    if args.json:
        ui.json_out(payload)
    else:
        verdict = payload["verdict"]
        ui.table(f"regression gate — {payload['machine']} [{verdict.upper()}]",
                 ["metric", "baseline", "observed", "delta", "band", "verdict"],
                 payload["rows"])
        if payload.get("regressions"):
            ui.panel("regressions", "\n".join(f"- {r}" for r in payload["regressions"]),
                     style="red")
    return 0 if payload["verdict"] == "pass" else 1


def cmd_benchmark(args) -> int:
    base = _base(args)
    sub = args.bench_cmd or "summary"
    if sub == "priors":
        data = benchmark.derive(base, write=not args.no_write)
        if args.json:
            ui.json_out(data)
        else:
            cal = data["calibration"]
            ui.kv_table("calibrated priors", {
                "best run": f"{cal.get('best_run')} ({cal.get('best_actions')} actions, "
                            f"{cal.get('best_dead_ends')} dead ends)",
                "worst run": f"{cal.get('worst_run')} ({cal.get('worst_actions')} actions, "
                             f"{cal.get('worst_dead_ends')} dead ends)",
                "stall threshold": data["stall"]["actions_threshold"],
                "dead-end rate": data["stall"]["dead_end_rate"],
                "priors file": str(config.rel(priors.priors_path(base), base)),
            })
            for e in data["keyword_costs"]:
                print(f"  cost {e['cost']:>4}  {e['category']:<18} /{e['pattern']}/")
        return 0
    if sub == "snapshot":
        ws = _ws(args, base)
        if not ws:
            return 2
        out = benchmark.snapshot(ws, base)
        print(f"snapshot: {config.rel(out, base)}")
        return 0
    if sub == "compare":
        paths = [Path(p) for p in (args.files or [])]
        if not paths:
            paths = benchmark.run_paths(base)
        if not paths:
            print("no benchmark runs found")
            return 0
        data = benchmark.compare(paths, base)
        if args.json:
            ui.json_out(data)
        else:
            ui.table("benchmark comparison", ["metric", *data["labels"]], data["rows"])
        return 0

    rows = benchmark.summary(base)
    if args.json:
        ui.json_out(rows)
        return 0
    ui.table("benchmark runs", ["file", "model", "machine", "actions", "dead ends",
                                "to root (s)", "to flag (s)"],
             [[r["file"], r["model"], r["machine"], r["actions"], r["dead_ends"],
               r["root_s"], r["flag_s"]] for r in rows])
    return 0


# ---- dashboard / steer / state -----------------------------------------

def cmd_dashboard(args) -> int:
    base = _base(args)
    cmd = [sys.executable, str(base / "scripts" / "dashboard.py"),
           "--root", str(base), "--host", args.host, "--port", str(args.port)]
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0


def cmd_steer(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    if args.agent not in AGENT_CHOICES:
        print(f"error: agent must be one of {', '.join(AGENT_CHOICES)}", file=sys.stderr)
        return 2
    msg = " ".join(args.message).strip()
    if not msg:
        print("error: message text required", file=sys.stderr)
        return 2

    def _m(s):
        s.post_message("user", args.agent, msg, "request")
    statex.locked_update(ws, _m)
    print(f"steered {args.agent}: {msg[:80]}")
    return 0


def cmd_state(args) -> int:
    base = _base(args)
    argv = list(args.state_args or [])
    if not argv:
        print("usage: bb state <workspace> <subcommand> [args...]", file=sys.stderr)
        return 2
    cmd = [sys.executable, str(base / "lib" / "state.py"), *argv]
    return subprocess.call(cmd)


# ---- assets (scope-aware diffing) ---------------------------------------

def cmd_assets(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    if args.assets_cmd == "scan":
        try:
            res = assets.scan(ws, base, mode=args.mode,
                              ingest_leads=args.ingest_leads)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.json:
            ui.json_out(res)
            return 0
        ui.kv_table(f"asset diff — {config.rel(ws, base)}", {
            "new": ", ".join(res["added"]) or "(none)",
            "gone": ", ".join(res["gone"]) or "(none)",
            "total tracked": res["total"],
            "rejected out-of-scope": res["rejected_out_of_scope"],
            "leads ingested": res["added_leads"],
        })
        return 0
    data = assets.show(ws)
    if args.json:
        ui.json_out(data)
        return 0
    if not data["total"]:
        print("(no assets tracked yet — `bb assets scan` after scope.md is filled)")
        return 0
    ui.kv_table(f"known assets — {config.rel(ws, base)}", {
        "updated": (data["updated_at"] and time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(data["updated_at"]))) or "never",
        "hosts": "\n".join(data["hosts"]) or "(none)",
        "urls": "\n".join(data["urls"][:20]) or "(none)",
        "total": data["total"],
    })
    return 0


# ---- composite action bundles -------------------------------------------

def _composites(base: Path) -> dict:
    data = config.read_json(base / "composites" / "manifest.json", default=None)
    return data if isinstance(data, dict) else {}


def cmd_composite(args) -> int:
    base = _base(args)
    comp = _composites(base)
    if args.composite_cmd == "show":
        rec = comp.get(args.name)
        if not rec:
            print(f"error: unknown composite {args.name!r}; choose from "
                  f"{', '.join(sorted(comp)) or '(none)'}", file=sys.stderr)
            return 2
        if args.json:
            ui.json_out(rec)
        else:
            ui.kv_table(f"composite — {args.name}", {
                "usage": rec.get("usage", ""),
                "description": rec.get("description", ""),
                "modes": ", ".join(rec.get("modes", [])),
                "replaces turns": rec.get("replaces_turns", "?"),
                "script": config.rel(base / "composites" / rec.get("script", ""),
                                     base),
            })
        return 0
    if not comp:
        print("no composites registered (composites/manifest.json missing or empty)")
        return 0
    rows = []
    for name in sorted(comp):
        rec = comp[name]
        script = base / "composites" / rec.get("script", "")
        rows.append([name, "ok" if script.exists() else "MISSING",
                     rec.get("usage", ""), rec.get("replaces_turns", "?")])
    if args.json:
        ui.json_out(comp)
        return 0
    ui.table("composite bundles (run via capture-command.py; one turn each)",
             ["name", "script", "usage", "~turns saved"], rows)
    print("invoke: python3 scripts/capture-command.py -- composites/<script> <args>")
    return 0


# ---- fingerprints / similar-box retrieval -------------------------------

def cmd_fingerprints(args) -> int:
    base = _base(args)
    recs = fingerprint.rebuild_index(base)
    if args.json:
        ui.json_out(recs)
        return 0
    if not recs:
        print("no fingerprintable workspaces (labs/HTB/machines/* with nmap output)")
        return 0
    rows = [[r["machine"], "yes" if r["solved"] else "no", len(r["ports"]),
             ", ".join(r["confirmed_categories"]) or "-", r["root_s"] or "-"]
            for r in recs]
    ui.table(f"fingerprint index — {len(recs)} machines",
             ["machine", "solved", "ports", "confirmed cats", "root_s"], rows)
    return 0


def cmd_similar(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    q = fingerprint.query_from_workspace(ws)
    if args.ports or args.services:
        if args.ports:
            q["ports"] = [p.strip() for p in args.ports.split(",") if p.strip()]
        if args.services:
            q["services"] = [s.strip() for s in args.services.split(",") if s.strip()]
    if not q["ports"] and not q["services"]:
        print("no recon fingerprint yet (no nmap output in the workspace) — "
              "pass --ports/--services or run recon first", file=sys.stderr)
        return 2
    hits = fingerprint.rank(q, base, top=args.top, min_sim=args.min_sim)
    bias = fingerprint.category_bias(q, base, min_sim=args.min_sim)
    if args.json:
        ui.json_out({"query": q, "hits": hits, "category_bias": bias})
        return 0
    if not hits:
        print("(no similar solved boxes — run `bb fingerprints rebuild` after solves)")
        return 0
    rows = [[h["machine"], f"{h['sim']:.2f}", ", ".join(h["ports"][:8]),
             ", ".join(h["confirmed_categories"]) or "-", h["root_s"] or "-"]
            for h in hits]
    ui.table("similar solved boxes", ["machine", "sim", "ports", "confirmed cats",
                                      "root_s"], rows)
    if bias:
        ui.panel("next-hyp bias", "\n".join(
            f"- {cat}: ×{b['mult']:.2f} (from {b['source']}, sim {b['sim']:.2f})"
            for cat, b in sorted(bias.items())), style="cyan")
    return 0


# ---- doctor / next-hyp --------------------------------------------------

def cmd_doctor(args) -> int:
    base = _base(args)
    checks = doctor.run(base, fix_writeups=args.fix_writeups,
                        fix_markers=args.fix_markers,
                        remove_root_burp=args.remove_root_burp, yes=args.yes,
                        manifest_out=not args.no_manifest)
    if args.json:
        ui.json_out(checks)
    else:
        rows = []
        for c in checks:
            mark = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}[c["status"]]
            rows.append([mark, c["name"], c["detail"]])
        ui.table("bb doctor", ["status", "check", "detail"], rows)
    return 1 if any(c["status"] == "fail" for c in checks) else 0


def cmd_next_hyp(args) -> int:
    base = _base(args)
    ws = _ws(args, base)
    if not ws:
        return 2
    pri = priors.load_priors(base)
    if args.apply:
        changed: list[dict] = []
        def _apply(s):
            changed.extend(priors.apply_to_state(s, pri))
        statex.locked_update(ws, _apply)
        if changed:
            print(f"updated {len(changed)} flat-default cost(s) from priors")
    st = TargetState.load(ws)
    bias = None
    if not args.no_sim_bias:
        try:
            q = fingerprint.query_from_workspace(ws)
            if q["ports"] or q["services"]:
                bias = fingerprint.category_bias(q, base)
        except Exception:
            bias = None
    rows = priors.adjusted(st, pri, bias=bias)
    if args.json:
        ui.json_out(rows)
        return 0
    table_rows = [[i + 1, r["id"], f"{r['score']:.2f}", f"{r['confidence']:.2f}",
                   f"{r['cost']:.2f}", f"{r['effective_cost']:.2f}", r["category"],
                   r.get("sim_hint") or "", (r["statement"] or "")[:60]]
                  for i, r in enumerate(rows)]
    ui.table(f"next hypotheses — {config.rel(ws, base)}",
             ["#", "id", "score", "conf", "stored cost", "eff. cost", "category",
              "sim hint", "statement"],
             table_rows)
    return 0


# ---- parser -------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS is important: these flags are copied into every subparser, and a
    # plain default=None would overwrite a value supplied before the subcommand.
    common.add_argument("--root", default=argparse.SUPPRESS,
                        help="repo root (default: BB_ROOT or the directory containing bb)")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")

    p = argparse.ArgumentParser(
        prog="bb", parents=[common],
        description="opencode-native bug-bounty/HTB automation CLI. Deterministic brain, "
                    "model proposes one turn at a time.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  bb init acme-program
  bb scope-check --program acme-program --full
  bb scope-check https://api.acme.test/v1 --program acme-program
  bb run --mode htb --machine Connected --target 10.129.122.68 --model dahl/zai-org/GLM-5.3-Flash
  bb run --resume labs/HTB/machines/Connected
  bb leads list --workspace labs/HTB/machines/Connected
  bb validate H-008 --workspace programs/infomaniak
  bb report H-008 --workspace programs/infomaniak
  bb skills kerberoast
  bb gate --workspace labs/HTB/machines/Connected --target 10.129.122.68 --cmd "nmap -sV 10.129.122.68" --keywords recon --mode htb
  bb dashboard --port 8765
  bb benchmark pin --machine Connected
  bb benchmark gate --machine Connected --snapshot benchmark/runs/Connected-new.json
  bb benchmark gate --machine Connected --run --max-minutes 40
  bb doctor
""")
    p.add_argument("--version", action="version", version=f"bb {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", parents=[common], help="create a program workspace")
    sp.add_argument("program")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("scope-check", parents=[common], help="deterministic scope gate")
    sp.add_argument("target", nargs="?", help="URL or host to check")
    sp.add_argument("--program", default=None)
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--mode", choices=["bounty", "htb", "bugbounty"], default="bounty")
    sp.add_argument("--full", action="store_true", help="enumerate the policy")
    sp.add_argument("--file", default=None, help="filter a file of URLs")
    sp.set_defaults(func=cmd_scope_check)

    sp = sub.add_parser("scope", parents=[common], help="scope maintenance")
    ssub = sp.add_subparsers(dest="scope_cmd", required=True)
    x = ssub.add_parser("sync", parents=[common],
                        help="operator-confirmed HTB scope refresh (old IP -> current IP)")
    x.add_argument("machine")
    x.add_argument("--target", default=None, help="current IP (default: resolve <machine>.htb)")
    x.add_argument("--yes", action="store_true", help="apply without an interactive prompt")
    x.set_defaults(func=cmd_scope_sync)

    sp = sub.add_parser("run", parents=[common], help="round-robin specialist run")
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--resume", nargs="?", const="", default=None,
                    help="resume a workspace (optionally pass the path)")
    sp.add_argument("--target", default=None)
    sp.add_argument("--machine", default=None)
    sp.add_argument("--program", default=None)
    sp.add_argument("--mode", choices=["htb", "bounty", "bugbounty"], default="htb")
    sp.add_argument("--model", default=None)
    sp.add_argument("--max-rounds", type=int, default=20)
    sp.add_argument("--parallel", type=int, default=None,
                    help="turns per round; default 5 for HTB, 1 for bounty")
    sp.add_argument("--max-workers", type=int, default=5)
    sp.add_argument("--agents", nargs="*", default=None,
                    help=f"subset of {', '.join(config.ROLE_SPECIALISTS)}")
    sp.add_argument("--timeout", type=int, default=900, help="per-turn seconds")
    sp.add_argument("--no-ui", action="store_true")
    sp.add_argument("--no-verify", action="store_true",
                    help="disable the second-opinion pass on hypothesis confirms")
    sp.add_argument("--dry-run", action="store_true",
                    help="write prompts/logs but do not invoke opencode")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("leads", parents=[common], help="lead board")
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--status", default=None)
    lsub = sp.add_subparsers(dest="leads_cmd")
    for name in ("list", "next", "ingest"):
        x = lsub.add_parser(name, parents=[common])
        x.add_argument("--workspace", default=argparse.SUPPRESS)
        x.add_argument("--status", default=argparse.SUPPRESS)
    lsub.choices["ingest"].add_argument("--recon-dir", default=None)
    x = lsub.add_parser("claim", parents=[common])
    x.add_argument("lead_id"); x.add_argument("--workspace", default=argparse.SUPPRESS)
    x.add_argument("--note", default=None)
    x = lsub.add_parser("touch", parents=[common])
    x.add_argument("lead_id"); x.add_argument("--workspace", default=argparse.SUPPRESS)
    x.add_argument("--status", default=argparse.SUPPRESS); x.add_argument("--note", default=None)
    x.add_argument("--finding-id", dest="finding_id", default=None)
    x = lsub.add_parser("add", parents=[common])
    x.add_argument("--workspace", default=argparse.SUPPRESS); x.add_argument("--skill", required=True)
    x.add_argument("--evidence", required=True); x.add_argument("--signal", default="")
    x.add_argument("--priority", default="med", choices=["high", "med", "low"])
    x.add_argument("--finding-id", dest="finding_id", default=None)
    sp.set_defaults(func=cmd_leads, workspace=None, status=None, leads_cmd=None)

    sp = sub.add_parser("gate", parents=[common],
                        help="deterministic critic gate before an action")
    sp.add_argument("--workspace", required=True)
    sp.add_argument("--agent", default="",
                    help="agent to attribute this verdict to (dashboard status)")
    sp.add_argument("--target", default="")
    sp.add_argument("--cmd", default="")
    sp.add_argument("--method", default="")
    sp.add_argument("--mode", choices=["bounty", "htb", "bugbounty"], default="bounty")
    sp.add_argument("--skill-checked", action="store_true")
    sp.add_argument("--keywords", default="")
    sp.add_argument("--trivial", action="store_true")
    sp.add_argument("--force", action="store_true",
                    help="allow a previously recorded command (explain what changed)")
    sp.add_argument("--allow-unsafe", action="store_true")
    sp.set_defaults(func=cmd_gate)

    sp = sub.add_parser("validate", parents=[common], help="4 gates + 7-question gate")
    sp.add_argument("finding_id", nargs="?", default=None)
    sp.add_argument("--file", default=None)
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--mode", choices=["bounty", "htb", "bugbounty"], default=None)
    sp.add_argument("--no-write", action="store_true")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("report", parents=[common], help="render a report draft")
    sp.add_argument("finding_id", nargs="?", default=None)
    sp.add_argument("--file", default=None)
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("skills", parents=[common], help="keyword skill lookup / audit")
    sp.add_argument("query", nargs="*")
    sp.add_argument("--limit", type=int, default=10)
    sp.add_argument("--audit", action="store_true")
    sp.add_argument("--prewarm", action="store_true")
    sp.set_defaults(func=cmd_skills)

    sp = sub.add_parser("learn", parents=[common], help="extract/approve/commit techniques")
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--approve", default=None)
    sp.add_argument("--reject", action="store_true")
    sp.add_argument("--commit", action="store_true")
    sp.add_argument("--show", default=None, metavar="CANDIDATE_ID")
    sp.add_argument("--edit", default=None, metavar="CANDIDATE_ID")
    sp.add_argument("--no-generate", action="store_true")
    sp.set_defaults(func=cmd_learn)

    sp = sub.add_parser("benchmark", parents=[common],
                        help="compare/summary/priors/pin/gate")
    bsub = sp.add_subparsers(dest="bench_cmd")
    for name in ("summary", "priors", "snapshot"):
        x = bsub.add_parser(name, parents=[common])
        x.add_argument("--workspace", default=None)
        x.add_argument("--no-write", action="store_true")
    x = bsub.add_parser("compare", parents=[common])
    x.add_argument("files", nargs="*")
    x = bsub.add_parser("pin", parents=[common],
                        help="pin a regression baseline from a saved run")
    x.add_argument("--machine", required=True)
    x.add_argument("--from", dest="run_from", default=None, metavar="RUN_JSON",
                   help="saved run to pin (default: fewest-action run for the machine)")
    x.add_argument("--actions-pct", type=float, default=None,
                   help="override unique_actions band (%%)")
    x.add_argument("--deadends-abs", type=float, default=None)
    x.add_argument("--deadends-pct", type=float, default=None)
    x.add_argument("--time-pct", type=float, default=None,
                   help="override time_to_* bands (%%)")
    x.add_argument("--confirmed-abs", type=float, default=None,
                   help="override hypotheses_confirmed absolute floor")
    x.add_argument("--notes", default="")
    x.set_defaults(func=cmd_benchmark_pin)
    x = bsub.add_parser("gate", parents=[common],
                        help="regression gate: compare a run against the pinned baseline")
    x.add_argument("--machine", required=True)
    x.add_argument("--snapshot", default=None, metavar="RUN_JSON",
                   help="saved run to compare (default: latest for the machine)")
    x.add_argument("--run", action="store_true",
                   help="re-run the lab in a scratch workspace, snapshot, compare, clean up")
    x.add_argument("--target", default=None)
    x.add_argument("--model", default=None)
    x.add_argument("--max-rounds", type=int, default=20)
    x.add_argument("--max-minutes", type=float, default=None,
                   help="wall-clock guard (default: 3x baseline time-to-root)")
    x.add_argument("--dry-run", action="store_true")
    x.add_argument("--keep", action="store_true", help="keep the gate scratch workspace")
    x.add_argument("--no-ui", action="store_true")
    x.set_defaults(func=cmd_benchmark_gate)
    sp.set_defaults(func=cmd_benchmark, files=None, workspace=None, no_write=False,
                    bench_cmd=None)

    sp = sub.add_parser("dashboard", parents=[common], help="start the web dashboard")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    sp.set_defaults(func=cmd_dashboard)

    sp = sub.add_parser("steer", parents=[common], help="inject a mailbox message")
    sp.add_argument("agent")
    sp.add_argument("message", nargs="+")
    sp.add_argument("--workspace", default=None)
    sp.set_defaults(func=cmd_steer)

    sp = sub.add_parser("state", parents=[common], help="pass-through to lib/state.py")
    sp.add_argument("state_args", nargs=argparse.REMAINDER)
    sp.set_defaults(func=cmd_state)

    sp = sub.add_parser("doctor", parents=[common], help="environment check + MANIFEST")
    sp.add_argument("--fix-writeups", action="store_true")
    sp.add_argument("--fix-markers", action="store_true",
                    help="delete zero-byte sessionresume_* leftovers")
    sp.add_argument("--remove-root-burp", action="store_true")
    sp.add_argument("--yes", action="store_true")
    sp.add_argument("--no-manifest", action="store_true")
    sp.set_defaults(func=cmd_doctor)

    sp = sub.add_parser("next-hyp", parents=[common], help="prior-adjusted hypothesis ranking")
    sp.add_argument("--workspace", required=True)
    sp.add_argument("--apply", action="store_true",
                    help="write calibrated costs back for flat-default hypotheses")
    sp.add_argument("--no-sim-bias", action="store_true",
                    help="disable the similar-box category bias (§2.1)")
    sp.set_defaults(func=cmd_next_hyp)

    sp = sub.add_parser("assets", parents=[common],
                        help="scope-aware asset store + diff (§3.1)")
    sp.add_argument("--workspace", default=None)
    asub = sp.add_subparsers(dest="assets_cmd")
    x = asub.add_parser("scan", parents=[common],
                        help="passive enum + rate-limited probe, diff vs last set")
    x.add_argument("--workspace", default=argparse.SUPPRESS)
    x.add_argument("--mode", choices=["bounty", "bugbounty", "htb"], default="bounty")
    x.add_argument("--ingest-leads", action="store_true",
                   help="add every new asset to the lead board")
    x = asub.add_parser("show", parents=[common])
    x.add_argument("--workspace", default=argparse.SUPPRESS)
    sp.set_defaults(func=cmd_assets, assets_cmd="show", mode="bounty",
                    ingest_leads=False)

    sp = sub.add_parser("composite", parents=[common],
                        help="list/show composite action bundles (§2.2)")
    csub = sp.add_subparsers(dest="composite_cmd")
    csub.add_parser("list", parents=[common])
    x = csub.add_parser("show", parents=[common])
    x.add_argument("name")
    sp.set_defaults(func=cmd_composite, composite_cmd="list", name=None)

    sp = sub.add_parser("fingerprints", parents=[common],
                        help="rebuild the solved-box fingerprint index (§2.1)")
    sp.add_argument("rebuild", nargs="?", default="rebuild", choices=["rebuild"])
    sp.set_defaults(func=cmd_fingerprints)

    sp = sub.add_parser("similar", parents=[common],
                        help="rank past solved boxes against this workspace's recon fingerprint")
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--ports", default=None, help="comma-separated, e.g. 22,443/tcp")
    sp.add_argument("--services", default=None, help="comma-separated, e.g. ssh,https")
    sp.add_argument("--top", type=int, default=3)
    sp.add_argument("--min-sim", type=float, default=0.05)
    sp.set_defaults(func=cmd_similar)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for name, default in (("root", None), ("json", False)):
        if not hasattr(args, name):
            setattr(args, name, default)
    # `--json` is inherited by every subparser; keep interactions with the
    # root flag stable when users put it before or after the subcommand.
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
