# PatchWatch — Project Context for Claude Code

## What this project is

PatchWatch is an AI-assisted code review & security vulnerability detector.
It scans GitHub PRs/diffs using static analysis tools (Bandit + Semgrep),
then adds two layers those tools don't have on their own:

1. **Reachability-based prioritization** — most scanners flag every match
   at the same severity regardless of whether an attacker can actually reach
   that code. We build a call graph from the AST (Abstract Syntax Tree) and
   run BFS/DFS from known entry points (e.g. FastAPI/Flask route handlers)
   to the vulnerable line. Reachable-from-a-public-route findings get
   ranked far above identical patterns sitting in dead code.
2. **LLM explain + fix layer** — instead of a raw rule ID like
   "B608 hardcoded_sql_expressions", we send the finding + surrounding code
   to an LLM and generate a plain-English "why this matters here" plus a
   concrete suggested fix.

## Who it's for

Small engineering teams / startups (typically <20 engineers) who ship code
without a dedicated security reviewer. The goal is to catch things like SQL
injection, command injection, and hardcoded secrets before they reach
production — with enough context that a generalist dev (not a security
specialist) understands why it matters and how to fix it.

## Key architectural decisions (already made, don't re-litigate these)

- **Reachability engine is Python-only for now.** Semgrep still scans all
  languages it supports, but only Python findings get the AST/reachability
  scoring boost. Non-Python findings are scored on severity/confidence alone.
  This is intentional — multi-language reachability is a documented "future
  work" item, not a v1 requirement. The `reachability.py` interface should
  stay generic (`get_call_graph(file) -> Graph`, `find_paths(...)`) so a
  language adapter can be dropped in later without touching scoring/LLM code.
- **No paid APIs or subscriptions for the tool itself.** Static analysis:
  Bandit (fully free CLI) + Semgrep OSS CLI (free, self-run, no cloud
  account — do NOT suggest Semgrep's paid Team/Cloud tier). LLM calls:
  Groq (primary, fast, generous free tier) with Google Gemini Flash (AI
  Studio free tier) as fallback when Groq's daily quota is exhausted.
- **Build order**: (1) standalone CLI tool with the full engine working
  locally, (2) package as a GitHub Action (no hosting needed — this is the
  MVP "shippable" milestone), (3) stretch goal only: GitHub App + hosted
  FastAPI backend + dashboard for historical trends. Don't jump ahead to
  webhooks/hosting before the CLI engine is solid.
- **Diff-aware scanning**: only scan changed lines/files in a PR, not the
  whole repo every time — keeps LLM calls cheap and results relevant.

## Data model

All scanner output gets normalized into one shared schema before anything
else touches it — see `patchwatch/models.py`, specifically the `Finding`
class. Any new scanner integration must produce `Finding` objects; don't
let scanner-specific formats leak past the `scanners/` layer.

Composite score formula (still to be tuned in analysis/scoring.py):
`score = f(base_severity, reachability, exposure_score, confidence, blast_radius)`

## Status (update this checklist as you complete items)

- [x] Project skeleton + dependencies (`pyproject.toml`)
- [x] Shared `Finding` schema (`patchwatch/models.py`)
- [x] Bandit runner + normalizer (`patchwatch/scanners/bandit_runner.py`)
- [ ] Semgrep runner + normalizer (`patchwatch/scanners/semgrep_runner.py`)
- [ ] AST-based call graph builder (`patchwatch/analysis/ast_graph.py`)
- [ ] Reachability engine, BFS/DFS from entry points (`patchwatch/analysis/reachability.py`)
- [ ] Composite scoring algorithm (`patchwatch/analysis/scoring.py`)
- [ ] LLM explain + fix layer (`patchwatch/llm/client.py`, `patchwatch/llm/prompts.py`)
- [ ] Git diff parsing — scan only changed lines (`patchwatch/diff/git_diff.py`)
- [ ] CLI entrypoint wiring it all together (`patchwatch/cli.py`)
- [ ] GitHub Action packaging
- [ ] (stretch) GitHub App + hosted dashboard

## Test fixture

`sample_repo/app.py` is a deliberately vulnerable FastAPI app used to
validate the pipeline. It contains a duplicated SQL-injection pattern: one
inside a public route (`get_user`, reachable) and one inside
`internal_debug_helper` (never called, unreachable) — this pair is the
canonical test case for proving the reachability engine actually works.
Don't "fix" the vulnerabilities in this file — they're intentional.

## Context for the human on this project

The person you're working with has ~7 months of professional experience.
Explain unfamiliar concepts (AST, call graphs, BFS/DFS, etc.) in plain
language when they come up, rather than assuming familiarity. This is a
learning-focused portfolio project, not just a "get it done fast" task —
prioritize clarity and teaching moments alongside working code.
