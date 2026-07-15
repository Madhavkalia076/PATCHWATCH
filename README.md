# PatchWatch

AI-assisted code review & security vulnerability detector.
Built step-by-step as a learning project — see conversation history for the
full design rationale.

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
   the exact gap our reachability engine (coming next) is designed to fix.

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

## Status

- [x] Project skeleton + dependencies
- [x] Shared `Finding` schema (`models.py`)
- [x] Bandit runner + normalizer
- [ ] Semgrep runner + normalizer
- [ ] AST-based call graph builder
- [ ] Reachability engine (BFS/DFS from entry points)
- [ ] Composite scoring algorithm
- [ ] LLM explain + fix layer (Groq primary, Gemini fallback)
- [ ] Git diff parsing (scan only changed lines)
- [ ] GitHub Action packaging
- [ ] (stretch) GitHub App + hosted dashboard
