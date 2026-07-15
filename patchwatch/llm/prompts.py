"""
Builds the prompt we send to an LLM for one Finding: a plain-English
explanation of why it matters here, plus a concrete suggested fix.
"""
from patchwatch.models import Finding

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
    """Returns (system_prompt, user_prompt) ready to send to an LLM."""
    user_prompt = f"""Vulnerability: {finding.title} ({finding.tool}, rule {finding.rule_id})
Severity: {finding.severity} | Confidence: {finding.confidence}
File: {finding.file_path}, line {finding.line_start}
{_REACHABILITY_NOTES[finding.reachable_from_entrypoint]}

Vulnerable code:
```
{finding.code_snippet}
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
