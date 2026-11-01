#!/usr/bin/env python3
"""
HTB Labs target provider for agentic-bug-hunter.

Adds "htb" as a target source alongside your live-program `programs/` dir.
HTB lab machines are pre-authorized under HTB's ToS for the duration of
your VPN session, so the scope-validation step your orchestrator runs
against live bounty `programs/*.json` can be skipped/simplified for
anything written here — still respect HTB's rules (one active machine
at a time, don't touch other players' VPN peers, no automated flag
farming beyond your own session).

Built against pyhtb 0.1.4's actual installed interface (inspected
directly via `dir()`/`inspect.signature`, not docs) - uses the `PyHTB`
unified client: `c.v5` for listing/searching machines, `c.v4` for
active-machine polling, spawn/terminate and VPN calls.

Requires: pip install pyhtb
Env:      HTB_APP_TOKEN   (app.hackthebox.com -> Settings -> App Tokens)

Usage:
    python3 htb_target_provider.py list [--query NAME] [--difficulty easy|medium|hard|insane]
    python3 htb_target_provider.py start <machine_id_or_name>
    python3 htb_target_provider.py active
    python3 htb_target_provider.py stop
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import pyhtb
except ImportError:
    sys.exit("pyhtb not installed - run: python3 -m pip install pyhtb --break-system-packages")

TOKEN = os.environ.get("HTB_APP_TOKEN")
if not TOKEN:
    sys.exit("Set HTB_APP_TOKEN (app.hackthebox.com -> Settings -> App Tokens)")

OUT_DIR = Path(__file__).resolve().parent.parent / "programs" / "htb"
OUT_DIR.mkdir(parents=True, exist_ok=True)

client = pyhtb.PyHTB(token=TOKEN)


def _unwrap(resp, attr="data"):
    """pyhtb's generated calls return typed response objects (or None on
    an unexpected status). Pull the useful field out, or bail with
    whatever info we have."""
    if resp is None:
        sys.exit("HTB API call failed (no response - bad token, network, or rate limit)")
    if hasattr(resp, "message"):
        # error-shaped response (V4Message / V5GenericErrorResponse)
        sys.exit(f"HTB API error: {getattr(resp, 'message', resp)}")
    return getattr(resp, attr, resp)


def list_machines(query=None, difficulty=None):
    kwargs = {"per_page": 100}
    if query:
        kwargs["keyword"] = query
    if difficulty:
        try:
            kwargs["difficulty"] = [pyhtb.V5GetMachinesDifficultyItem(difficulty.lower())]
        except ValueError:
            sys.exit(f"difficulty must be one of: {[e.value for e in pyhtb.V5GetMachinesDifficultyItem]}")

    resp = client.v5.get_machines(**kwargs)
    items = _unwrap(resp, "data")
    for m in items:
        active_flag = " [active]" if getattr(m, "active", False) else ""
        print(f"{m.id:>6}  {m.name:<20} {m.os:<8} {m.difficulty_text:<8}{active_flag}")


def resolve_id(name):
    resp = client.v5.get_machines(per_page=100, keyword=name)
    items = _unwrap(resp, "data")
    for m in items:
        if m.name.lower() == name.lower():
            return m.id
    sys.exit(f"no machine named {name!r}")


def start_machine(ident):
    machine_id = int(ident) if ident.isdigit() else resolve_id(ident)
    client.v4.post_vm_spawn(body=pyhtb.V4SpawnRequest(machine_id=machine_id))

    for _ in range(30):
        resp = client.v4.get_machine_active()
        info = _unwrap(resp, "info")
        if info and getattr(info, "id", None) == machine_id and getattr(info, "ip", None):
            write_target(info)
            print(f"up: {info.name} -> {info.ip}")
            return
        time.sleep(5)
    sys.exit("timed out waiting for IP assignment - check `htb vpn status` / server region")


def write_target(info):
    target = {
        "source": "htb",
        "name": info.name,
        "target": info.ip,
        "expires_at": getattr(info, "expires_at", None),
        "vpn_server_id": getattr(info, "vpn_server_id", None),
        "scope": {
            "hosts": [info.ip],
            "note": "HTB lab machine - pre-authorized for this VPN session only",
        },
    }
    path = OUT_DIR / f"{info.name.lower()}.json"
    path.write_text(json.dumps(target, indent=2))
    print(f"wrote {path}")


def show_active():
    resp = client.v4.get_machine_active()
    info = _unwrap(resp, "info")
    if not info:
        print("no active machine")
        return
    print(json.dumps(
        {k: getattr(info, k) for k in
         ("id", "name", "ip", "expires_at", "is_spawning", "vpn_server_id")
         if hasattr(info, k)},
        indent=2, default=str,
    ))


def stop_machine():
    resp = client.v4.get_machine_active()
    info = _unwrap(resp, "info")
    if not info or not getattr(info, "id", None):
        sys.exit("no active machine to stop")
    client.v4.post_vm_terminate(body=pyhtb.V4SpawnRequest(machine_id=info.id))
    print(f"stopped {info.name}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list")
    sp.add_argument("--query")
    sp.add_argument("--difficulty")

    sp = sub.add_parser("start")
    sp.add_argument("ident")

    sub.add_parser("active")
    sub.add_parser("stop")

    args = p.parse_args()
    action = {
        "list": lambda: list_machines(args.query, args.difficulty),
        "start": lambda: start_machine(args.ident),
        "active": show_active,
        "stop": stop_machine,
    }[args.cmd]

    try:
        action()
    except pyhtb.httpx.HTTPError as e:
        sys.exit(f"network/HTTP error talking to HTB: {e}")
