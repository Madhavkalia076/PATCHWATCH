"""
Walks a CallGraph (built by ast_graph.py) to answer the question this whole
project exists for: starting from a public entry point (a FastAPI/Flask
route handler), can execution ever reach a given vulnerable line?

Kept separate from ast_graph.py so a future language adapter only has to
produce a CallGraph -- everything in this file works off that one generic
shape and doesn't care whether it came from Python, JS, or anything else.
"""
from collections import deque
from pathlib import Path

from patchwatch.analysis.ast_graph import CallGraph
from patchwatch.models import Finding


def find_paths(graph: CallGraph, start: str) -> set[str]:
    """
    Every function name reachable from `start` by following `calls` edges,
    including `start` itself.

    This is a BFS (breadth-first search): explore every function `start`
    calls directly first, then everything *those* call, and so on,
    outward one call-hop at a time, until nothing new is found.
    """
    visited = {start}
    queue = deque([start])

    while queue:
        current = queue.popleft()
        node = graph.functions.get(current)
        if node is None:
            continue  # calls a name with no definition in this file (builtin, import, etc.) -- dead end

        for callee in node.calls:
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)

    return visited


def reachable_functions(graph: CallGraph) -> set[str]:
    """Every function name reachable from ANY entry point in this graph."""
    reachable: set[str] = set()
    for entry in graph.entrypoints():
        reachable |= find_paths(graph, entry.name)
    return reachable


def mark_reachability(graph: CallGraph, findings: list[Finding]) -> list[Finding]:
    """
    Sets `reachable_from_entrypoint` on every Finding (in place) whose
    `file_path` matches this graph's file. Findings from other files are
    left untouched, so this can be called once per file over a combined
    findings list from every scanner.

    A Finding whose line isn't inside any known function (e.g. module-level
    code like a hardcoded secret) gets `None` -- reachability genuinely
    doesn't apply there, that's different from "checked and unreachable".
    """
    reachable = reachable_functions(graph)
    graph_path = Path(graph.file_path)

    for finding in findings:
        # Compare as paths, not raw strings -- scanners and our own graph
        # builder don't always agree on '/' vs '\', even on the same file.
        if Path(finding.file_path) != graph_path:
            continue

        func = graph.function_containing_line(finding.line_start)
        finding.reachable_from_entrypoint = None if func is None else func.name in reachable

    return findings


if __name__ == "__main__":
    # Quick manual test: run this file directly to see reachability scoring
    # applied to real scanner output on the sample app.
    import sys

    from patchwatch.analysis.ast_graph import get_call_graph
    from patchwatch.scanners.bandit_runner import run_bandit

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "sample_repo"

    graph = get_call_graph(f"{target_dir}/app.py")
    findings = run_bandit(target_dir)
    mark_reachability(graph, findings)

    for f in findings:
        print(f"[{f.severity}] {f.title} @ {f.file_path}:{f.line_start}  reachable={f.reachable_from_entrypoint}")
