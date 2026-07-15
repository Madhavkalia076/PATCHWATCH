"""
Runs Bandit against a directory and converts its raw JSON output into
our normalized `Finding` objects.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from patchwatch.models import Finding, Severity, Confidence

# Bandit uses the words "LOW"/"MEDIUM"/"HIGH" already, so mapping is 1:1.
# We still write an explicit map (instead of just re-using the string) so that
# if Bandit ever changes its wording, only this one line needs to change.
_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}
_CONFIDENCE_MAP = {
    "LOW": Confidence.LOW,
    "MEDIUM": Confidence.MEDIUM,
    "HIGH": Confidence.HIGH,
}


def run_bandit(target_dir: str) -> list[Finding]:
    """
    Runs `bandit -r <target_dir>` and returns a list of normalized Findings.

    We ask Bandit for JSON output (-f json) instead of its default colored
    terminal text, because JSON is what a program should parse -- the
    colored text format is meant for a human reading a terminal, not for us.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    subprocess.run(
        ["bandit", "-r", target_dir, "-f", "json", "-o", output_path],
        capture_output=True,  # don't spam our own terminal with Bandit's logs
        text=True,
    )
    # Note: we deliberately don't check the return code here. Bandit exits
    # with a NON-zero code whenever it finds ANY issue (that's normal for
    # security scanners -- non-zero means "issues found", not "crashed").

    raw = json.loads(Path(output_path).read_text())
    Path(output_path).unlink()  # clean up the temp file

    findings: list[Finding] = []
    for item in raw.get("results", []):
        finding = Finding(
            id=f"bandit:{item['test_id']}:{item['filename']}:{item['line_number']}",
            tool="bandit",
            rule_id=item["test_id"],
            title=item["test_name"],
            description=item["issue_text"],
            file_path=item["filename"],
            line_start=item["line_number"],
            line_end=item["line_range"][-1] if item.get("line_range") else item["line_number"],
            severity=_SEVERITY_MAP.get(item["issue_severity"], Severity.MEDIUM),
            confidence=_CONFIDENCE_MAP.get(item["issue_confidence"], Confidence.MEDIUM),
            cwe_id=item.get("issue_cwe", {}).get("id"),
            code_snippet=item.get("code", ""),
        )
        findings.append(finding)

    return findings


if __name__ == "__main__":
    # Quick manual test: run this file directly to sanity-check the converter.
    import sys
    results = run_bandit(sys.argv[1] if len(sys.argv) > 1 else "sample_repo")
    for f in results:
        print(f"[{f.severity}] {f.title} @ {f.file_path}:{f.line_start}")
