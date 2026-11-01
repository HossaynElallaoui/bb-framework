"""Run a command and save reproducible command metadata and output."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def now():
    return datetime.now(timezone.utc)


def infer_method(command: list[str]) -> tuple[str, bool]:
    """Best-effort HTTP verb inference so the central method policy still
    applies when the caller forgets `--method`. Non-HTTP shell commands default
    to GET, which is always allowed."""
    text = " ".join(command)
    for pat in (r"(?:-X|--request)\s*([A-Za-z]+)", r"-X([A-Za-z]+)"):
        m = re.search(pat, text)
        if m:
            return m.group(1).upper(), True
    if re.search(r"\bcurl\b|\bhttpie\b|\bhttp\s", text) and re.search(
            r"(?:-d|--data|--data-raw|--data-binary|--json|-F|--form)\b", text):
        return "POST", True
    return "GET", False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Existing recon or evidence directory")
    parser.add_argument("--timeout", type=float, default=300, help="Seconds (default: 300)")
    # Central safety controls: rate ceiling, circuit breaker, method policy.
    # Without --workspace the runner behaves exactly as before (standalone use).
    parser.add_argument("--workspace", type=Path, default=None,
                        help="workspace whose scope.env/policy governs this command")
    parser.add_argument("--host", default=None, help="rate-limit key (default: 'default')")
    parser.add_argument("--rate", type=float, default=None, help="requests/minute override")
    parser.add_argument("--no-rate-check", action="store_true")
    parser.add_argument("--method", default=None, help="HTTP verb for the method policy")
    parser.add_argument("--mode", default="bounty", choices=["bounty", "htb"])
    parser.add_argument("--allow-unsafe", action="store_true",
                        help="permit PUT/PATCH/DELETE in bounty mode")
    # Split on the conventional `--` separator BEFORE argparse: REMAINDER is
    # greedy and would otherwise swallow our own --workspace/--rate flags.
    argv = sys.argv[1:]
    if "--" not in argv:
        parser.error("Supply a command after --.")
    sep = argv.index("--")
    opt_argv, command = argv[:sep], argv[sep + 1:]
    args = parser.parse_args(opt_argv)
    if not command:
        parser.error("Supply a command after --.")
    if args.timeout <= 0:
        parser.error("Timeout must be greater than zero.")
    if not args.output.is_dir():
        parser.error("Output must be an existing directory.")

    # ---- central policy checks (deterministic, before the process starts) ----
    policy_meta = {}
    rate_limiter = None
    breaker = None
    host = args.host or "default"
    if args.workspace:
        import sys as _sys
        from pathlib import Path as _Path
        _root = _Path(__file__).resolve().parent.parent
        if str(_root) not in _sys.path:
            _sys.path.insert(0, str(_root))
        try:
            from lib.bb import policy as bb_policy
            from lib.bb import scope as bb_scope
        except Exception as exc:  # noqa: BLE001 - never break capture on import drift
            print(f"warning: bb policy unavailable ({exc}); proceeding without it",
                  file=sys.stderr)
            bb_policy = bb_scope = None
        if bb_policy:
            policy_meta["mode"] = args.mode
            method, inferred = (args.method.upper(), False) if args.method else infer_method(command)
            policy_meta["method"] = method
            if inferred:
                policy_meta["method_inferred"] = True
            ok, why = bb_policy.SafeMethodPolicy.allow(
                method, args.mode, allow_unsafe=args.allow_unsafe)
            if not ok:
                print(f"DENY: {why}", file=sys.stderr)
                return 2
            rate = args.rate
            if rate is None and bb_scope:
                try:
                    pol = bb_scope.load_policy(workspace=args.workspace, mode=args.mode)
                    rate = pol.rate_per_min if pol else None
                except Exception:
                    rate = None
            if rate is None:
                env_rate = os.environ.get("BB_RATE_PER_MIN")
                rate = float(env_rate) if env_rate else None
            rate_limiter = bb_policy.RateLimiter(args.workspace, rate)
            policy_meta["rate_per_min"] = rate
            breaker = bb_policy.CircuitBreaker(args.workspace)
            allowed, why = breaker.allow(host)
            if not allowed:
                print(f"DENY: {why}", file=sys.stderr)
                return 2
            if rate and not args.no_rate_check:
                wait = rate_limiter.enforce(host)
                policy_meta["rate_wait_s"] = round(wait, 3)
                if wait > 0:
                    print(f"rate limit: slept {wait:.1f}s ({rate}/min, host={host})",
                          file=sys.stderr)

    started = now()
    run = args.output.resolve() / (started.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
    run.mkdir(mode=0o700)
    metadata = {
        "argv": command,
        "cwd": str(Path.cwd()),
        "started_at": started.isoformat(),
        "timeout_seconds": args.timeout,
        **policy_meta,
    }
    return_code = 1
    with (run / "stdout.txt").open("wb") as stdout, (run / "stderr.txt").open("wb") as stderr:
        try:
            # A process group lets timeouts stop child processes as well.
            import signal

            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                return_code = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return_code = 124
                metadata["error"] = "Command timed out; process group stopped."
            except KeyboardInterrupt:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                return_code = 130
                metadata["error"] = "Interrupted by user."
        except OSError as error:
            return_code = 127
            metadata["error"] = str(error)

    if breaker is not None:
        breaker.record(host, success=(return_code == 0))
    metadata.update({"finished_at": now().isoformat(), "return_code": return_code})
    (run / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Saved command output: {run}")
    print(f"Return code: {return_code}")
    return return_code if return_code >= 0 else 128 - return_code


if __name__ == "__main__":
    sys.exit(main())
