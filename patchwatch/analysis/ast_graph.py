"""
Builds a call graph from a single Python file's AST (Abstract Syntax Tree --
Python's own parsed representation of source code as a tree of objects like
FunctionDef and Call, instead of raw text).

We walk that tree to answer two questions for every function in the file:
  1. What line range does it span? (so a scanner Finding's line number can
     be mapped back to the function that contains it)
  2. What other functions does it call, and is it itself an entry point
     (e.g. a FastAPI/Flask route handler)?

This module only builds the graph. Walking it to answer "can an attacker
reach this line?" is reachability.py's job, kept separate so a future
language adapter (JS, Go, ...) only needs to implement this file's
interface -- get_call_graph(file) -> Graph -- without touching the
reachability/scoring code downstream.
"""
import ast
from dataclasses import dataclass, field
from pathlib import Path

# Decorators that mark a function as reachable from the outside world.
# We key off the *attribute name* (e.g. the "get" in @app.get(...)) rather
# than the object it's called on, since a project might name its FastAPI/
# Flask instance "app", "api", "router", anything -- the HTTP method name is
# the one thing that's consistent across Flask and FastAPI route decorators.
_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


@dataclass
class FunctionNode:
    """One function definition inside the scanned file."""
    name: str
    line_start: int
    line_end: int
    is_entrypoint: bool
    calls: set[str] = field(default_factory=set)


@dataclass
class CallGraph:
    """All functions in a file, plus who calls whom."""
    file_path: str
    functions: dict[str, FunctionNode] = field(default_factory=dict)

    def function_containing_line(self, line: int) -> FunctionNode | None:
        """Which function (if any) does this source line belong to?
        Used to map a scanner Finding's line number back onto this graph."""
        for func in self.functions.values():
            if func.line_start <= line <= func.line_end:
                return func
        return None

    def entrypoints(self) -> list[FunctionNode]:
        """Every function reachable directly from the outside world."""
        return [f for f in self.functions.values() if f.is_entrypoint]


def get_call_graph(file_path: str) -> CallGraph:
    """
    Parses a single Python file and returns its CallGraph: every function
    (top-level or nested), the line range it spans, whether it's an entry
    point, and which other functions (by name) it calls.

    Note: this tracks calls by bare name only (e.g. `get_connection()`),
    not through attributes or imports (e.g. `some_module.helper()`). That's
    good enough for the question the reachability engine actually asks --
    "does a route handler eventually call this vulnerable function?" --
    within a single file. Cross-file/cross-module call tracking is future
    work, same as multi-language support.
    """
    source = Path(file_path).read_text()
    tree = ast.parse(source, filename=file_path)

    graph = CallGraph(file_path=file_path)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        graph.functions[node.name] = FunctionNode(
            name=node.name,
            line_start=node.lineno,
            line_end=node.end_lineno,
            is_entrypoint=_is_route_handler(node),
            calls=_called_function_names(node),
        )

    return graph


def _is_route_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if this function is decorated with something like
    @app.get(...), @router.post(...), etc."""
    for decorator in func.decorator_list:
        # A decorator is either a call (@app.get("/x")) or a bare
        # attribute (@app.get) -- unwrap the call to get at the attribute.
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_METHODS:
            return True
    return False


def _called_function_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every bare function name called anywhere inside this function's body,
    e.g. `get_connection()` -> {"get_connection"}. Method calls like
    `conn.execute(...)` are skipped -- we only track calls to our own
    functions, not to library/object methods."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
    return names


if __name__ == "__main__":
    # Quick manual test: run this file directly to sanity-check the graph.
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_repo/app.py"
    graph = get_call_graph(path)
    for func in graph.functions.values():
        marker = "ENTRYPOINT" if func.is_entrypoint else "          "
        print(f"[{marker}] {func.name}() lines {func.line_start}-{func.line_end}  calls={func.calls or '{}'}")
