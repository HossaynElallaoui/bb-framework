#!/usr/bin/env python3
"""
Render a side-by-side comparison table from two or more filled-in
benchmark run files (see template.json).

Usage:
    python3 compare.py runs/glm-5.3-flash-forest.json runs/claude-free-forest.json
"""

import json
import sys

FIELDS = [
    ("auto", "unique_actions", "Commands executed"),
    ("auto", "dead_ends", "Dead ends"),
    ("auto", "time_to_user_s", "Time to user (s)"),
    ("auto", "time_to_root_s", "Time to root (s)"),
    ("judged", "recon_quality", "Recon quality /10"),
    ("judged", "hypothesis_quality", "Hypothesis quality /10"),
    ("judged", "tool_selection", "Tool selection /10"),
    ("judged", "web_reasoning", "Web reasoning /10"),
    ("judged", "ad_reasoning", "AD reasoning /10"),
    ("judged", "privilege_escalation", "Privesc /10"),
    ("judged", "false_assumptions", "False assumptions #"),
    ("judged", "hints_required", "Hints required"),
    ("judged", "context_tokens_used", "Context tokens used"),
]


def load(path):
    with open(path) as f:
        return json.load(f)


def main(paths):
    runs = [load(p) for p in paths]
    labels = [f"{r.get('model', '?')} / {r.get('machine', '?')}" for r in runs]

    col_w = max(24, max(len(l) for l in labels) + 2)
    print(f"{'':30}" + "".join(l.ljust(col_w) for l in labels))
    print("-" * (30 + col_w * len(runs)))
    for section, key, label in FIELDS:
        row = [str(r.get(section, {}).get(key, "-")) for r in runs]
        print(f"{label:30}" + "".join(v.ljust(col_w) for v in row))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: compare.py <run1.json> <run2.json> [...]")
    main(sys.argv[1:])
