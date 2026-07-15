"""
Sends a Finding's details to an LLM to get a plain-English explanation and
a suggested fix, filling in `llm_explanation` and `llm_fix_suggestion`.

Groq is tried first (fast, generous free tier). If that call fails for any
reason -- most commonly its daily free-tier quota being exhausted -- we
fall back to Google Gemini Flash (also free tier, no paid account needed
for either). See CLAUDE.md for why we deliberately never reach for a paid
API here.
"""
import os
import re

import groq
from dotenv import load_dotenv
from google import genai

from patchwatch.llm.prompts import build_prompt
from patchwatch.models import Finding

load_dotenv()  # picks up GROQ_API_KEY / GEMINI_API_KEY from a local .env if present

_GROQ_MODEL = "llama-3.1-8b-instant"
# gemini-2.0-flash and gemini-2.5-flash-lite both stopped granting this
# project free-tier quota (Gemini's free lineup shifts over time) --
# gemini-3.1-flash-lite is confirmed "Free of charge" on Google's current
# pricing page (ai.google.dev/gemini-api/docs/pricing) and verified working.
_GEMINI_MODEL = "gemini-3.1-flash-lite"


def explain_finding(finding: Finding) -> Finding:
    """
    Sets `llm_explanation` and `llm_fix_suggestion` on `finding` (in place)
    and returns it. Tries Groq first, falls back to Gemini on any failure.

    If both fail (no keys configured, both quotas exhausted, network down,
    etc.), we record the error as the explanation instead of raising --
    one bad LLM call shouldn't take down an entire scan report.
    """
    system_prompt, user_prompt = build_prompt(finding)

    try:
        text = _call_groq(system_prompt, user_prompt)
    except Exception as groq_error:
        try:
            text = _call_gemini(system_prompt, user_prompt)
        except Exception as gemini_error:
            finding.llm_explanation = (
                f"LLM explanation unavailable (Groq: {groq_error}; Gemini: {gemini_error})"
            )
            finding.llm_fix_suggestion = None
            return finding

    finding.llm_explanation, finding.llm_fix_suggestion = _split_response(text)
    return finding


def _call_groq(system_prompt: str, user_prompt: str) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set")

    client = groq.Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=_GROQ_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content


def _call_gemini(system_prompt: str, user_prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=_GEMINI_MODEL,
        contents=user_prompt,
        config={"system_instruction": system_prompt, "temperature": 0.2},
    )
    return response.text


def _split_response(text: str) -> tuple[str, str | None]:
    """Splits the LLM's two-section reply into (explanation, fix). Falls
    back to treating the whole reply as the explanation if the model
    didn't follow the requested section headers exactly -- LLMs don't
    always obey formatting instructions perfectly, so this shouldn't crash
    the whole pipeline when that happens.

    Headers are matched with optional `**` around them (`\*{0,2}`) because
    models routinely bold their own section headers despite being asked
    for plain text -- without that, the leftover `**` markers show up as
    stray asterisks in the output."""
    match = re.search(r"\*{0,2}SUGGESTED FIX\*{0,2}[:\s]*\n?(.*)", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return text.strip(), None

    fix = match.group(1).strip()
    explanation = re.sub(
        r"\*{0,2}WHY THIS MATTERS HERE\*{0,2}[:\s]*\n?", "", text[: match.start()], flags=re.IGNORECASE
    ).strip()
    return explanation, fix


if __name__ == "__main__":
    # Quick manual test: run the full pipeline on the sample app, then get
    # an LLM explanation for just the highest-scored finding (to avoid
    # burning API quota on every run).
    import sys

    from patchwatch.analysis.ast_graph import get_call_graph
    from patchwatch.analysis.reachability import mark_reachability
    from patchwatch.analysis.scoring import score_finding
    from patchwatch.scanners.bandit_runner import run_bandit

    target_dir = sys.argv[1] if len(sys.argv) > 1 else "sample_repo"

    graph = get_call_graph(f"{target_dir}/app.py")
    findings = run_bandit(target_dir)
    mark_reachability(graph, findings)
    for f in findings:
        score_finding(f, graph)

    top = max(findings, key=lambda f: f.composite_score)
    explain_finding(top)

    print(f"{top.title} @ {top.file_path}:{top.line_start} (score {top.composite_score})")
    print()
    print("WHY THIS MATTERS:")
    print(top.llm_explanation)
    print()
    print("SUGGESTED FIX:")
    print(top.llm_fix_suggestion)
