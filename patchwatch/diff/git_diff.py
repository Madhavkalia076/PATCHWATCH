"""
Parses a git diff to find out which lines actually changed, so a scan can
be limited to a PR's new/modified code instead of the whole repo -- keeps
LLM calls cheap and avoids flagging pre-existing issues nobody touched in
this PR (see CLAUDE.md: "diff-aware scanning").
"""
from pathlib import Path

import git

from patchwatch.models import Finding


def get_changed_lines(repo_path: str, base_ref: str = "main") -> dict[str, set[int]]:
    """
    Returns {file_path: {line numbers added in this diff}} comparing
    `base_ref` against the current working tree -- so it covers both
    committed commits on this branch AND any uncommitted edits, the same
    thing `git diff <base_ref>` shows you on the command line.

    Only ADDED lines are tracked. A deleted line doesn't exist anymore for
    a scanner to flag, so there's nothing to report on it.
    """
    repo = git.Repo(repo_path, search_parent_directories=True)
    diff_text = repo.git.diff(base_ref, "--unified=0")
    return _parse_unified_diff(diff_text)


def _parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    """
    Walks a unified diff's raw text (not GitPython's Diff objects -- those
    don't expose line numbers, only the hunk headers in the raw text do)
    and records, per file, which line numbers were added.

    With --unified=0 (no surrounding context lines), every line inside a
    hunk is either a '+' (added) or '-' (deleted) line -- there's no
    unchanged context to skip.
    """
    changed: dict[str, set[int]] = {}
    current_file = None
    current_line = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[len("+++ b/"):]
            changed.setdefault(current_file, set())
        elif line.startswith("@@"):
            current_line = _hunk_start_line(line)
        elif line.startswith("+"):
            changed[current_file].add(current_line)
            current_line += 1
        # '-' lines were removed from the old file, so they don't occupy a
        # line number in the new file -- nothing to record, nothing to advance.

    return changed


def _hunk_start_line(hunk_header: str) -> int:
    """Extracts the starting line number in the NEW file from a hunk
    header like '@@ -12,0 +13,3 @@ def foo():' -> 13."""
    new_file_part = hunk_header.split("+", 1)[1].split()[0]  # "13,3" or just "13"
    return int(new_file_part.split(",")[0])


def filter_to_changed_lines(findings: list[Finding], changed_lines: dict[str, set[int]]) -> list[Finding]:
    """
    Keeps only findings whose line is inside `changed_lines` for that file.
    Findings in files the diff doesn't touch at all are dropped too.

    Paths are compared with pathlib rather than as raw strings -- git
    reports paths relative to the repo root with forward slashes, while
    scanners report whatever separator the OS uses, same class of mismatch
    already hit and fixed in reachability.py.
    """
    changed_by_path = {Path(f): lines for f, lines in changed_lines.items()}
    return [
        f for f in findings
        if f.line_start in changed_by_path.get(Path(f.file_path), set())
    ]
