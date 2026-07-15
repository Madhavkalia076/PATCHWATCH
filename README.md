# PatchWatch

AI-assisted code review & security vulnerability detector.

PatchWatch scans code (currently Python, via Bandit + Semgrep) and adds two
things off-the-shelf scanners don't give you on their own:

1. **Reachability-based prioritization** — most scanners flag every match at
   the same severity, whether or not an attacker could ever actually reach
   that code. PatchWatch builds a call graph from the AST and walks it
   (BFS/DFS) from known entry points (e.g. FastAPI/Flask route handlers) to
   each vulnerable line. A finding reachable from a public route gets ranked
   far above an identical pattern sitting in dead code.
2. **LLM explain + fix layer** — instead of a raw rule ID like
   `B608 hardcoded_sql_expressions`, PatchWatch sends the finding and its
   surrounding code to an LLM and generates a plain-English "why this
   matters here" plus a concrete suggested fix.

## Who it's for

Small engineering teams / startups (typically <20 engineers) shipping code
without a dedicated security reviewer. The goal is to catch things like SQL
injection, command injection, and hardcoded secrets before they reach
production — with enough context that a generalist developer, not a
security specialist, understands why it matters and how to fix it.

## How it works

```
scanners (Bandit, Semgrep)
        │  raw tool-specific output
        ▼
  normalize into a shared `Finding` schema
        │
        ▼
  reachability engine (AST call graph + BFS/DFS from entry points)
        │  is this finding actually reachable by an attacker?
        ▼
  composite scoring (severity + reachability + exposure + blast radius)
        │
        ▼
  LLM explain + fix layer (Groq primary, Gemini Flash fallback)
        │
        ▼
  CLI output / GitHub Action PR comment
```

Every scanner's output gets normalized into one shared `Finding` schema
(`patchwatch/models.py`) before anything else touches it, so adding a new
scanner only requires writing one converter — nothing downstream needs to
know Bandit and Semgrep report things differently.

## Key design decisions

- **Reachability is Python-only for now.** Semgrep still scans every
  language it supports, but only Python findings get the AST/reachability
  scoring boost — everything else is scored on severity/confidence alone.
  Multi-language reachability is documented future work, not a v1
  requirement.
- **No paid APIs or subscriptions for the tool itself.** Static analysis
  runs entirely on free, self-hosted CLIs (Bandit, Semgrep OSS — not
  Semgrep's paid Team/Cloud tier). LLM calls use Groq's free tier as
  primary, with Google Gemini Flash (AI Studio free tier) as fallback.
- **Diff-aware scanning.** Only changed lines/files in a PR get scanned, not
  the whole repo every time — keeps LLM calls cheap and results relevant.
- **Build order:** (1) standalone CLI with the full engine working locally,
  (2) package as a GitHub Action — no hosting required, this is the
  "shippable" MVP milestone, (3) stretch goal: GitHub App + hosted
  dashboard for historical trends.

## Setup (in VS Code / your local machine)

1. Create a virtual environment (keeps this project's packages separate from
   everything else on your machine):
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # on Windows: venv\Scripts\activate
   ```

2. Install the project in "editable" mode (`-e` means: if you edit the code,
   changes take effect immediately, no reinstall needed):
   ```bash
   pip install -e .
   ```

3. Sanity-check the scanners are installed:
   ```bash
   bandit --version
   semgrep --version
   ```

4. Run our Bandit wrapper against the deliberately-vulnerable sample app:
   ```bash
   python3 -m patchwatch.scanners.bandit_runner sample_repo
   ```
   You should see 4 findings printed, including two identical SQL-injection
   warnings (one reachable from a public route, one in dead code) — this is
   the exact gap the reachability engine is designed to fix.

## Project layout

```
patchwatch/
├── patchwatch/
│   ├── models.py          # shared `Finding` data schema (all scanners normalize into this)
│   ├── scanners/
│   │   └── bandit_runner.py   # converts Bandit's JSON output -> Finding objects
│   ├── analysis/           # (next up) reachability/scoring engine
│   ├── llm/                # (next up) explain + fix-suggestion layer
│   └── diff/                # (later) git diff parsing for PR-scoped scanning
├── sample_repo/
│   └── app.py               # deliberately vulnerable test file
├── tests/
└── pyproject.toml
```

`sample_repo/app.py` is a deliberately vulnerable FastAPI app used to
validate the pipeline end-to-end. It contains a duplicated SQL-injection
pattern: one inside a public route (`get_user`, reachable) and one inside
`internal_debug_helper` (never called, unreachable) — this pair is the
canonical test case for proving the reachability engine actually works.
The vulnerabilities in this file are intentional; don't "fix" them.

## Status

- [x] Project skeleton + dependencies
- [x] Shared `Finding` schema (`patchwatch/models.py`)
- [x] Bandit runner + normalizer (`patchwatch/scanners/bandit_runner.py`)
- [x] Semgrep runner + normalizer (`patchwatch/scanners/semgrep_runner.py`)
- [x] AST-based call graph builder (`patchwatch/analysis/ast_graph.py`)
- [x] Reachability engine — BFS/DFS from entry points (`patchwatch/analysis/reachability.py`)
- [x] Composite scoring algorithm (`patchwatch/analysis/scoring.py`)
- [ ] LLM explain + fix layer (`patchwatch/llm/client.py`, `patchwatch/llm/prompts.py`)
- [ ] Git diff parsing — scan only changed lines (`patchwatch/diff/git_diff.py`)
- [ ] CLI entrypoint wiring it all together (`patchwatch/cli.py`)
- [ ] GitHub Action packaging
- [ ] (stretch) GitHub App + hosted dashboard
