"""
Command-line entrypoint that wires the whole pipeline together: run both
scanners, build a call graph per Python file, mark reachability, score
every finding, optionally get an LLM explanation, then print a report
ranked by "what should I look at first" instead of scanner output order.

`pip install -e .` registers this as the `patchwatch` command -- see
pyproject.toml's [project.scripts].
"""
import os
import sys

import click
import git
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Windows' console defaults to cp1252, which can't render the Unicode
# ellipsis Rich uses when truncating table cells -- shows up as garbled "?"
# characters otherwise. Force UTF-8 so the report renders correctly
# regardless of the terminal's codepage (same class of issue fixed in
# semgrep_runner.py's subprocess output handling).
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

from patchwatch.analysis.ast_graph import CallGraph, get_call_graph
from patchwatch.analysis.reachability import mark_reachability
from patchwatch.analysis.scoring import score_finding
from patchwatch.diff.git_diff import filter_to_changed_lines, get_changed_lines
from patchwatch.llm.client import explain_finding
from patchwatch.models import Finding
from patchwatch.scanners.bandit_runner import run_bandit
from patchwatch.scanners.semgrep_runner import run_semgrep

console = Console()

_SEVERITY_STYLE = {"LOW": "dim", "MEDIUM": "yellow", "HIGH": "bold red", "CRITICAL": "bold white on red"}


@click.command()
@click.argument("target_dir", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--explain", is_flag=True,
    help="Get an LLM explanation + suggested fix for each finding (uses Groq/Gemini API quota).",
)
@click.option(
    "--min-score", default=0.0, show_default=True,
    help="Only show findings scoring at or above this composite score (0-100).",
)
@click.option(
    "--diff", "base_ref", default=None,
    help="Only show findings on lines changed since this git ref (e.g. main). "
         "Turns a whole-repo scan into a PR-scoped one.",
)
@click.option(
    "--fail-on-findings", is_flag=True,
    help="Exit with a non-zero status if any findings remain after filtering -- "
         "for use as a CI gate (e.g. the GitHub Action). Off by default so "
         "local runs are just a report, not a build failure.",
)
def main(
    target_dir: str, explain: bool, min_score: float, base_ref: str | None, fail_on_findings: bool
) -> None:
    """Scan TARGET_DIR for vulnerabilities, prioritized by real-world reachability."""
    console.print(f"[bold]Scanning {target_dir}...[/bold]")
    findings = run_bandit(target_dir) + run_semgrep(target_dir)

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    if base_ref:
        try:
            changed_lines = get_changed_lines(target_dir, base_ref)
        except git.exc.GitCommandError:
            raise click.ClickException(
                f"Couldn't diff against '{base_ref}' -- is it a valid branch/commit, "
                f"and is {target_dir} inside a git repo?"
            )
        findings = filter_to_changed_lines(findings, changed_lines)
        if not findings:
            console.print(f"[green]No findings on lines changed since {base_ref}.[/green]")
            return

    _score_all(findings)

    findings = [f for f in findings if f.composite_score >= min_score]
    findings.sort(key=lambda f: f.composite_score, reverse=True)

    if explain:
        # Filter/sort happens before this, so --min-score also controls how
        # many LLM calls (and how much API quota) get spent.
        console.print(f"Getting LLM explanations for {len(findings)} finding(s)...")
        for finding in findings:
            explain_finding(finding)

    _print_report(findings, target_dir, explain)

    if fail_on_findings and findings:
        sys.exit(1)


def _score_all(findings: list[Finding]) -> None:
    """
    Builds one call graph per unique file with findings, then scores every
    finding against it. Non-Python files (from Semgrep's multi-language
    rules) get an empty CallGraph instead of a real one -- reachability is
    Python-only for now (see CLAUDE.md), so an empty graph naturally makes
    those findings fall back to "reachability unknown" scoring, the same
    path a Python finding takes when its line isn't inside any function.
    """
    graphs: dict[str, CallGraph] = {}

    for finding in findings:
        if finding.file_path in graphs:
            continue
        if finding.file_path.endswith(".py"):
            graphs[finding.file_path] = get_call_graph(finding.file_path)
        else:
            graphs[finding.file_path] = CallGraph(file_path=finding.file_path)

    for graph in graphs.values():
        mark_reachability(graph, findings)

    for finding in findings:
        score_finding(finding, graphs[finding.file_path])


def _print_report(findings: list[Finding], target_dir: str, explain: bool) -> None:
    table = Table(title=f"{len(findings)} finding(s)")
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    table.add_column("Tool")
    table.add_column("Title")
    table.add_column("Location")
    table.add_column("Reachable")

    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "")
        reachable = {True: "yes", False: "no", None: "unknown"}[f.reachable_from_entrypoint]
        # Relative to target_dir instead of the full path -- every row
        # otherwise repeats the same scanned-directory prefix.
        location = os.path.relpath(f.file_path, target_dir)
        table.add_row(
            f"{f.composite_score:.1f}",
            f"[{style}]{f.severity}[/{style}]",
            f.tool,
            f.title,
            f"{location}:{f.line_start}",
            reachable,
        )

    console.print(table)

    if explain:
        for f in findings:
            body = f"[bold]Why this matters:[/bold]\n{f.llm_explanation}\n\n[bold]Suggested fix:[/bold]\n{f.llm_fix_suggestion}"
            console.print(Panel(body, title=f"{f.title} @ {f.file_path}:{f.line_start}"))


if __name__ == "__main__":
    main()
