"""
Shared data schema for PatchWatch.

Every scanner (Bandit, Semgrep, future additions) outputs findings in its own
format. Everything downstream (scoring, LLM explanations, PR comments) should
only ever deal with THIS shape, so we only need to write one converter per
scanner instead of teaching every later step about every tool's quirks.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized severity levels. Bandit/Semgrep use slightly different
    words and scales, so we map everything onto this one enum."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """How sure the SCANNER is that this is a real issue (not a false positive)."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Finding(BaseModel):
    """One single issue reported by a scanner, in our normalized shape."""

    id: str = Field(..., description="Stable unique id, e.g. 'bandit:B608:app.py:22'")
    tool: str = Field(..., description="Which scanner found this: 'bandit' or 'semgrep'")
    rule_id: str = Field(..., description="The scanner's own rule identifier, e.g. 'B608'")
    title: str = Field(..., description="Short human-readable name of the issue")
    description: str = Field(..., description="Scanner's explanation of the issue")
    file_path: str
    line_start: int
    line_end: int
    severity: Severity
    confidence: Confidence
    cwe_id: Optional[int] = Field(None, description="Common Weakness Enumeration id, if known")
    code_snippet: str = Field("", description="The actual vulnerable code, for LLM context")

    # These get filled in LATER by our own analysis stages (not by the scanner):
    reachable_from_entrypoint: Optional[bool] = Field(
        None, description="Set by reachability engine: can attacker-facing code reach this line?"
    )
    exposure_score: Optional[float] = Field(
        None, description="0-1: how exposed is the entry point (public/unauthenticated = higher)"
    )
    blast_radius: Optional[int] = Field(
        None, description="How many other functions call the vulnerable function"
    )
    composite_score: Optional[float] = Field(
        None, description="Final 0-100 priority score combining all signals above"
    )
    llm_explanation: Optional[str] = Field(None, description="Plain-English 'why this matters here'")
    llm_fix_suggestion: Optional[str] = Field(None, description="Suggested code fix from the LLM")


class ScanResult(BaseModel):
    """The full output of scanning one repo/PR: just a list of findings
    plus a bit of metadata."""

    repo_path: str
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
