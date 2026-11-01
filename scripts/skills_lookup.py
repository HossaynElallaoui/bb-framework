#!/usr/bin/env python3
"""
Search your real, already-on-disk skill libraries by keyword, instead of
relying on a specialist's built-in knowledge or an invented skills/
convention that doesn't match what you actually have.

Indexes two shapes of skill, both common across your directories:

  packaged:  <root>/<slug>/SKILL.md          (e.g. bug-bounty-skills/sqli/SKILL.md)
  flat:      <root>/<category>/<name>.md     (e.g. skills/web/xss-bot-privileged-action.md)

Which roots to search comes from lib/skill_roots.json - edit that file if
your layout changes, not this script. As shipped it covers:

  packaged_roots: bug-bounty-skills, cybersecurity-skills/skills,
                   Anthropic-Cybersecurity-Skills/skills,
                   agentic-bug-hunter/skills
  flat_roots:     skills   (your own learned/generated skills -
                   see modes/htb.md step 9, which writes here)

Scoring is plain token overlap against the slug/filename and (for
packaged skills) the SKILL.md's first ~20 non-empty lines - no embeddings,
no network call, so it's near-free to call every time a specialist is
about to generate a hypothesis.

Usage:
    python3 scripts/skills_lookup.py idor bola
    python3 scripts/skills_lookup.py kerberoast --limit 5
    python3 scripts/skills_lookup.py "active directory acl" --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "lib" / "skill_roots.json"
CACHE_PATH = ROOT / ".skills_index.json"

# Module-level memo for in-process callers, plus an on-disk cache so separate
# `opencode run` subprocesses (each of which runs this script fresh) share one
# prewarmed index instead of re-walking 850+ directories every turn.
_INDEX_CACHE: list[dict] | None = None
_INDEX_STAMP: str | None = None


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


# Common pentest/bug-bounty abbreviations whose full form doesn't share a
# substring with the short form (so the fuzzy substring check in
# _fuzzy_overlap can't catch them on its own) - "privesc" isn't a
# substring of "privilege", unlike "kerberoast"/"kerberoasting" which
# substring matching already handles fine. Expand query tokens only (not
# every indexed entry - keeps index building cheap); this list is short
# and meant to be grown, not exhaustive.
SYNONYMS: dict[str, set[str]] = {
    "privesc": {"privilege", "escalation"},
    "recon": {"reconnaissance"},
    "xxe": {"external", "entity"},
    "ssrf": {"forgery"},
    "rce": {"execution"},
    "lfi": {"inclusion"},
    "rfi": {"inclusion"},
    "exfil": {"exfiltration"},
    "ad": {"directory"},
    "idor": {"authorization", "object"},
    "priv": {"privilege"},
    "creds": {"credential", "credentials"},
}


def _expand_query(q_tokens: set[str]) -> set[str]:
    expanded = set(q_tokens)
    for t in q_tokens:
        expanded |= SYNONYMS.get(t, set())
    return expanded


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"missing {CONFIG_PATH} - see lib/skill_roots.json for the expected shape")
    return json.loads(CONFIG_PATH.read_text())


def _snippet(path: Path, max_lines: int = 20) -> str:
    """First handful of non-empty lines, stripped of markdown noise -
    usually the title/description, which is what we want to match on."""
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    out = []
    for line in lines:
        line = line.strip().lstrip("#-* ").strip()
        if line and not line.startswith("---"):
            out.append(line)
        if len(out) >= max_lines:
            break
    return " ".join(out)


def _root_stamp(config: dict | None = None) -> str:
    """Newest directory mtime across every configured root + the config file.

    Walking directories (not files) is cheap and still invalidates when a new
    skill file is added, because its parent directory's mtime changes."""
    config = config or _load_config()
    newest = CONFIG_PATH.stat().st_mtime if CONFIG_PATH.exists() else 0.0
    for name in list(config.get("packaged_roots", [])) + list(config.get("flat_roots", [])):
        d = ROOT / name
        if not d.exists():
            continue
        for dirpath, _dirnames, _filenames in os.walk(d):
            try:
                newest = max(newest, os.stat(dirpath).st_mtime)
            except OSError:
                pass
    return str(int(newest))


def _cached(stamp: str) -> list[dict] | None:
    global _INDEX_CACHE, _INDEX_STAMP
    if _INDEX_CACHE is not None and _INDEX_STAMP == stamp:
        return _INDEX_CACHE
    try:
        data = json.loads(CACHE_PATH.read_text())
    except (OSError, ValueError):
        return None
    if data.get("stamp") != stamp:
        return None
    entries = []
    for e in data.get("entries", []):
        e = dict(e)
        e["tokens"] = set(e.get("tokens", []))
        entries.append(e)
    _INDEX_CACHE, _INDEX_STAMP = entries, stamp
    return entries


def _store_cache(entries: list[dict], stamp: str) -> None:
    global _INDEX_CACHE, _INDEX_STAMP
    _INDEX_CACHE, _INDEX_STAMP = entries, stamp
    payload = {"stamp": stamp, "generated_at": int(time.time()),
               "entries": [{**e, "tokens": sorted(e["tokens"])} for e in entries]}
    try:
        tmp = CACHE_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, CACHE_PATH)
    except OSError:
        pass


def prewarm() -> int:
    """Build (or load) the shared index and return its entry count."""
    return len(build_index(use_cache=True))


def build_index(use_cache: bool = True) -> list[dict]:
    config = _load_config()
    stamp = _root_stamp(config)
    if use_cache:
        hit = _cached(stamp)
        if hit is not None:
            return hit
    entries: list[dict] = []

    for root_name in config.get("packaged_roots", []):
        root = ROOT / root_name
        if not root.exists():
            continue
        for skill_md in root.rglob("SKILL.md"):
            slug = skill_md.parent.name
            snippet = _snippet(skill_md)
            entries.append({
                "path": str(skill_md.relative_to(ROOT)),
                "slug": slug,
                "source": root_name,
                "kind": "packaged",
                "tokens": _tokenize(slug) | _tokenize(snippet),
                "snippet": snippet[:200],
            })

    for root_name in config.get("flat_roots", []):
        root = ROOT / root_name
        if not root.exists():
            continue
        for md_file in root.rglob("*.md"):
            if md_file.name.upper() == "SKILL.MD" or md_file.name == "README.md":
                continue
            category = md_file.parent.name
            slug = md_file.stem
            snippet = _snippet(md_file)
            entries.append({
                "path": str(md_file.relative_to(ROOT)),
                "slug": slug,
                "source": f"{root_name}/{category}",
                "kind": "flat",
                "tokens": _tokenize(slug) | _tokenize(category) | _tokenize(snippet),
                "snippet": snippet[:200],
            })

    if use_cache:
        _store_cache(entries, stamp)
    return entries


def _fuzzy_overlap(q_tokens: set[str], entry_tokens: set[str]) -> int:
    """Exact token matches, plus a cheap fallback for word-form variants
    that are everywhere in this domain (kerberoast/kerberoasting,
    privesc/privilege, exfil/exfiltration) - no real stemmer, just
    substring containment either direction for tokens of 5+ chars (short
    tokens would false-positive too easily, e.g. 'os' inside 'post')."""
    exact = q_tokens & entry_tokens
    fuzzy = set()
    for qt in q_tokens:
        if len(qt) < 5:
            continue
        for et in entry_tokens:
            if len(et) < 5:
                continue
            if qt in et or et in qt:
                fuzzy.add(qt)
                break
    return len(exact) * 2 + len(fuzzy - exact)  # exact hits still rank higher


def search(query: str, limit: int = 10) -> list[dict]:
    q_tokens = _tokenize(query)
    if not q_tokens:
        return []

    scored = []
    for entry in build_index():
        base_score = _fuzzy_overlap(q_tokens, entry["tokens"])
        if base_score == 0:
            continue
        # slug/filename matches count extra - a hit on "sqli" the slug
        # means more than a hit on "sqli" buried in a 20-line snippet
        slug_tokens = _tokenize(entry["slug"])
        slug_bonus = _fuzzy_overlap(q_tokens, slug_tokens)
        scored.append((base_score + slug_bonus, entry))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [e for _, e in scored[:limit]]


def audit(min_similarity: float = 0.72, max_pairs: int = 200) -> list[dict]:
    """Surface near-duplicate skill clusters for manual merge decisions.

    Heuristic only: token Jaccard over slug + short caption, with an inverted
    index so ~900 entries do not become 400k full comparisons. Nothing is
    deleted or merged automatically.
    """
    entries = build_index()
    sigs = []
    inverted: dict[str, set[int]] = {}
    for i, e in enumerate(entries):
        sig = _tokenize(e["slug"]) | _tokenize(e.get("snippet", "")[:140])
        sigs.append(sig)
        for tok in sig:
            if len(tok) >= 4:
                inverted.setdefault(tok, set()).add(i)
    candidates: set[tuple[int, int]] = set()
    for tok, idxs in inverted.items():
        if len(idxs) < 2 or len(idxs) > 80:
            continue
        ordered = sorted(idxs)
        for a_pos in range(len(ordered)):
            for b_pos in range(a_pos + 1, len(ordered)):
                candidates.add((ordered[a_pos], ordered[b_pos]))
    out = []
    for a, b in candidates:
        sa, sb = sigs[a], sigs[b]
        if not sa or not sb:
            continue
        jac = len(sa & sb) / len(sa | sb)
        if jac >= min_similarity:
            out.append({
                "similarity": round(jac, 3),
                "a": entries[a]["path"], "b": entries[b]["path"],
                "slug_a": entries[a]["slug"], "slug_b": entries[b]["slug"],
                "source_a": entries[a]["source"], "source_b": entries[b]["source"],
            })
    out.sort(key=lambda d: d["similarity"], reverse=True)
    return out[:max_pairs]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("query", nargs="+", help="keywords, e.g. idor bola, or kerberoast")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.add_argument("--prewarm", action="store_true", help="build the shared on-disk index")
    p.add_argument("--audit", action="store_true", help="list near-duplicate clusters")
    args = p.parse_args()

    if args.prewarm:
        n = prewarm()
        print(f"skills index warmed: {n} entries")
        return

    if args.audit:
        clusters = audit()
        if args.json:
            print(json.dumps(clusters, indent=2))
        else:
            for c in clusters[:args.limit]:
                print(f"{c['similarity']:.2f}  {c['a']}\n       {c['b']}")
            print(f"{len(clusters)} candidate pairs — manual merge only, nothing deleted")
        return

    results = search(" ".join(args.query), limit=args.limit)

    if args.json:
        print(json.dumps(
            [{k: v for k, v in r.items() if k != "tokens"} for r in results],
            indent=2,
        ))
        return

    if not results:
        print("(no matching skills found - try broader keywords, or check lib/skill_roots.json)")
        return

    for r in results:
        print(f"[{r['kind']:>8}] {r['path']}")
        if r["snippet"]:
            print(f"           {r['snippet'][:120]}")


if __name__ == "__main__":
    main()
