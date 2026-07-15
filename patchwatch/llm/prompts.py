"""
Builds the prompt we send to an LLM for one Finding: a plain-English
explanation of why it matters here, plus a concrete suggested fix.
"""
import re

from patchwatch.models import Finding

# Scrubs values that look like hardcoded credentials before code leaves this
# machine for an LLM API -- otherwise a "hardcoded secret" finding would
# forward the actual secret value to Groq/Gemini as part of explaining it.
# Two heuristics: a quoted string assigned to a suspiciously-named variable
# (API_KEY = "..."), and well-known API key prefixes regardless of variable
# name. This is best-effort, like any regex-based secret scanner -- it
# reduces the odds of a leak, it doesn't replace not committing real
# secrets in the first place.
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)(\b\w*(?:secret|token|password|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)\w*\s*[:=]\s*)(['"])(.*?)\2"""
)
_SECRET_PREFIX_PATTERN = re.compile(
    r"\b(sk-[a-zA-Z0-9]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,})\b"
)


def _redact_secrets(code: str) -> str:
    """Replaces anything that looks like a hardcoded credential with a
    placeholder, keeping the surrounding code (and the fact that a secret
    *was* there) intact so the LLM can still comment on the pattern."""
    code = _SECRET_ASSIGNMENT_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}***REDACTED***{m.group(2)}", code)
    code = _SECRET_PREFIX_PATTERN.sub("***REDACTED***", code)
    return code


_SYSTEM_PROMPT = (
    "You are a security code reviewer helping a generalist developer (not "
    "a security specialist) understand and fix a vulnerability. Be direct "
    "and concrete: explain the real-world risk in plain language, then "
    "give a specific code fix. Do not just restate the scanner's own "
    "description back at the developer -- assume they've already read it."
)

_REACHABILITY_NOTES = {
    True: (
        "This code IS reachable from a public route PatchWatch found -- "
        "a real attacker could trigger it directly."
    ),
    False: (
        "This code is NOT currently reachable from any entry point "
        "PatchWatch could find in this file -- it may be dead code. Say so, "
        "but still explain why it would matter if that ever changes."
    ),
    None: "Reachability could not be determined for this line.",
}


def build_prompt(finding: Finding) -> tuple[str, str]:
    """Returns (system_prompt, user_prompt) ready to send to an LLM.

    Only the code embedded in this prompt is redacted -- `finding` itself
    is left untouched, so the CLI's own report still shows the real code
    to the person running it."""
    code_snippet = _redact_secrets(finding.code_snippet)
    user_prompt = f"""Vulnerability: {finding.title} ({finding.tool}, rule {finding.rule_id})
Severity: {finding.severity} | Confidence: {finding.confidence}
File: {finding.file_path}, line {finding.line_start}
{_REACHABILITY_NOTES[finding.reachable_from_entrypoint]}

Vulnerable code:
```
{code_snippet}
```

Scanner's raw description (for your context, don't just repeat it): {finding.description}

Respond in exactly two sections, using these two headers verbatim:

WHY THIS MATTERS HERE
2-3 sentences, specific to this code and its reachability -- not a generic
definition of the vulnerability class.

SUGGESTED FIX
A concrete code change (a short snippet is fine), not just abstract advice
like "use parameterized queries".
"""
    return _SYSTEM_PROMPT, user_prompt
