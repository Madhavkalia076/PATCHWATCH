"""
Combines everything we know about a Finding -- its severity, how confident
the scanner is, and whether it's actually reachable from an entry point --
into one 0-100 `composite_score` per finding, so a report can be sorted by
"what should I look at first" instead of just "what did the scanner flag".

The exact weights below are a first-pass heuristic, not a proven formula --
CLAUDE.md flags this as "still to be tuned". The important part is that all
five signals from the data model (severity, reachability, exposure,
confidence, blast radius) actually participate, so tuning later just means
adjusting numbers here, not restructuring the pipeline.
"""
from patchwatch.analysis.ast_graph import CallGraph
from patchwatch.analysis.reachability import find_paths
from patchwatch.models import Confidence, Finding, Severity

# How many of the 100 possible points each severity level starts with,
# before reachability/confidence adjust it.
_SEVERITY_POINTS = {
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 100,
}

# How much we trust the scanner's own judgment call -- a LOW-confidence
# finding gets scaled down, since it's more likely to be a false positive.
_CONFIDENCE_MULTIPLIER = {
    Confidence.LOW: 0.6,
    Confidence.MEDIUM: 0.8,
    Confidence.HIGH: 1.0,
}

# Points added per function that calls into the vulnerable one (directly or
# transitively), capped so blast radius can nudge a score but never
# dominate severity/reachability.
_BLAST_RADIUS_POINTS_PER_CALLER = 3
_BLAST_RADIUS_CAP = 15


def score_finding(finding: Finding, graph: CallGraph) -> Finding:
    """
    Sets `exposure_score`, `blast_radius`, and `composite_score` on a single
    Finding (in place) and returns it.

    Assumes `mark_reachability()` has already run for this finding, i.e.
    `finding.reachable_from_entrypoint` is already set -- reachability is a
    call-graph question, scoring is just about weighing signals that are
    already computed.
    """
    finding.exposure_score = _exposure_score(finding.reachable_from_entrypoint)

    func = graph.function_containing_line(finding.line_start)
    finding.blast_radius = _blast_radius(graph, func.name) if func else 0

    severity_points = _SEVERITY_POINTS[finding.severity]
    confidence_multiplier = _CONFIDENCE_MULTIPLIER[finding.confidence]
    blast_radius_points = min(
        finding.blast_radius * _BLAST_RADIUS_POINTS_PER_CALLER, _BLAST_RADIUS_CAP
    )

    raw_score = (severity_points * finding.exposure_score * confidence_multiplier) + blast_radius_points
    finding.composite_score = round(min(raw_score, 100), 1)

    return finding


def _exposure_score(reachable: bool | None) -> float:
    """
    How exposed this finding is to the outside world, as a 0-1 multiplier
    on severity:
      - True  (reachable from a public route): fully exposed.
      - False (checked, and nothing calls it): heavily discounted, but not
        zero -- dead code today can become reachable after a refactor, so
        it shouldn't vanish from a report entirely.
      - None  (not inside any function we could analyze, e.g. a hardcoded
        secret sitting at module level): treated as moderately exposed by
        default. Module-level code runs unconditionally at import time, so
        it isn't gated behind any entry point the way function calls are --
        we just don't have a real signal here yet, hence "moderate" rather
        than "full".
    """
    if reachable is True:
        return 1.0
    if reachable is False:
        return 0.15
    return 0.7


def _blast_radius(graph: CallGraph, function_name: str) -> int:
    """
    How many other functions call this one, directly or transitively --
    a rough proxy for "how much of the app is entangled with this exact
    function". Computed by checking, for every other function in the file,
    whether it can eventually reach `function_name` via the call graph.
    """
    count = 0
    for name in graph.functions:
        if name != function_name and function_name in find_paths(graph, name):
            count += 1
    return count


if __name__ == "__main__":
    # Quick manual test: run the full pipeline built so far (scan -> mark
    # reachability -> score) on the sample app and print a ranked report.
    import sys

    from patchwatch.analysis.ast_graph import get_call_graph
    from patchwatch.analysis.reachability import mark_reachability
    from patchwatch.scanners.bandit_runner import run_bandit

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "sample_repo"

    graph = get_call_graph(f"{target_dir}/app.py")
    findings = run_bandit(target_dir)
    mark_reachability(graph, findings)
    for f in findings:
        score_finding(f, graph)

    for f in sorted(findings, key=lambda f: f.composite_score, reverse=True):
        print(
            f"{f.composite_score:>5.1f}  [{f.severity}] {f.title} @ {f.file_path}:{f.line_start}  "
            f"(reachable={f.reachable_from_entrypoint}, blast_radius={f.blast_radius})"
        )
