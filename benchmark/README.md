# HTB Benchmark

Goal: compare free models on reasoning quality, not just "did it solve the
box" — repeated actions and dead ends matter as much as a root flag.

## Per-run process

1. Run a machine through `agents/orchestrator.md` in HTB mode as normal.
2. When it finishes (or you cut it off): `python3 ../lib/state.py
   labs/HTB/machines/<name> benchmark` — this gives you the `auto` block
   (unique actions, dead ends, time-to-user/root) straight from state.json.
3. Copy `template.json` to `runs/<model>-<machine>.json`, paste the `auto`
   block in, fill in `model`/`machine`/`difficulty`.
4. Fill the `judged` block. Two options:
   - **Manual**: read `postmortem.md` + the transcript yourself, score
     1-10 on recon/hypothesis/tool-selection/web/AD/privesc quality, count
     false assumptions and hints needed.
   - **LLM-judged**: feed the transcript + postmortem to a separate model
     (ideally not the one that ran the lab) with a rubric asking for the
     same fields back as JSON. Keeps it consistent across runs and removes
     your own bias toward whichever model you like.

## Comparing runs

```bash
python3 compare.py runs/glm-5.3-flash-forest.json runs/claude-free-forest.json
```

Prints a side-by-side table. Add more paths for more models.

## What this is actually measuring

`unique_actions` and `dead_ends` come straight from state.json, so they're
hard numbers, not vibes — a model that solves the box in 40 unique actions
with 2 dead ends is doing something structurally different (and better)
than one that needed 140 actions and 20 dead ends, even if both eventually
got root. That's the free-model comparison the orchestrator setup makes
possible: speed-to-root alone hides whether the model is reasoning or
brute-forcing its way there.
