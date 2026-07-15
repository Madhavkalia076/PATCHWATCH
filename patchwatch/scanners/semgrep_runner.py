"""
Runs Semgrep against a directory and converts its raw JSON output into
our normalized `Finding` objects.
"""
import json
import re
import subprocess
import tempfile
from pathlib import Path

from patchwatch.models import Finding, Severity, Confidence

# Semgrep uses ERROR/WARNING/INFO, which is a different scale than Bandit's
# LOW/MEDIUM/HIGH -- there's no exact match, so this mapping is our own
# judgment call about how urgent each level should be treated as.
_SEVERITY_MAP = {
    "INFO": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}
_CONFIDENCE_MAP = {
    "LOW": Confidence.LOW,
    "MEDIUM": Confidence.MEDIUM,
    "HIGH": Confidence.HIGH,
}
_CWE_NUMBER_RE = re.compile(r"CWE-(\d+)")


def run_semgrep(target_dir: str) -> list[Finding]:
    """
    Runs `semgrep --config=auto <target_dir>` and returns a list of
    normalized Findings.

    We ask Semgrep for JSON output (--json) instead of its default terminal
    report, same reason as the Bandit runner: JSON is what a program should
    parse, the colored report is for a human.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    subprocess.run(
        ["semgrep", "--config=auto", target_dir, "--json", "-o", output_path],
        capture_output=True,  # don't spam our own terminal with Semgrep's logs
        text=True,
        encoding="utf-8",  # Semgrep's progress output uses non-ASCII characters
        errors="replace",  # (box-drawing, checkmarks); Windows' default codec chokes on them
    )
    # Note: like the Bandit runner, we deliberately don't check the return
    # code -- Semgrep exits non-zero whenever it finds issues, that's normal.

    raw = json.loads(Path(output_path).read_text())
    Path(output_path).unlink()  # clean up the temp file

    findings: list[Finding] = []
    for item in raw.get("results", []):
        extra = item["extra"]
        metadata = extra.get("metadata", {})
        line_start = item["start"]["line"]
        line_end = item["end"]["line"]

        finding = Finding(
            id=f"semgrep:{item['check_id']}:{item['path']}:{line_start}",
            tool="semgrep",
            rule_id=item["check_id"],
            title=item["check_id"].rsplit(".", 1)[-1],
            description=extra["message"],
            file_path=item["path"],
            line_start=line_start,
            line_end=line_end,
            severity=_SEVERITY_MAP.get(extra["severity"], Severity.MEDIUM),
            confidence=_CONFIDENCE_MAP.get(metadata.get("confidence"), Confidence.MEDIUM),
            cwe_id=_first_cwe_number(metadata.get("cwe")),
            code_snippet=_read_lines(item["path"], line_start, line_end),
        )
        findings.append(finding)

    return findings


def _first_cwe_number(cwe_list: list[str] | None) -> int | None:
    """Semgrep reports CWEs as strings like 'CWE-89: SQL Injection'; we only
    keep the numeric id, to match the plain int Bandit already gives us."""
    if not cwe_list:
        return None
    match = _CWE_NUMBER_RE.search(cwe_list[0])
    return int(match.group(1)) if match else None


def _read_lines(file_path: str, line_start: int, line_end: int) -> str:
    """Semgrep's JSON output only includes the matched source code if you're
    logged in to Semgrep Cloud (its 'lines' field is otherwise a placeholder
    string), so we read the snippet ourselves from disk instead. Line
    numbers here are 1-indexed, same as Semgrep reports them."""
    lines = Path(file_path).read_text().splitlines()
    return "\n".join(lines[line_start - 1:line_end])


if __name__ == "__main__":
    # Quick manual test: run this file directly to sanity-check the converter.
    import sys
    results = run_semgrep(sys.argv[1] if len(sys.argv) > 1 else "sample_repo")
    for f in results:
        print(f"[{f.severity}] {f.title} @ {f.file_path}:{f.line_start}")
