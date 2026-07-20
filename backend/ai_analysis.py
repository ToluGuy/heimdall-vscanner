# backend/ai_analysis.py

import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("vapt.ai")

AI_PROVIDER    = os.environ.get("AI_PROVIDER", "").strip().lower()
AI_API_KEY     = os.environ.get("AI_API_KEY", "").strip()
AI_MODEL       = os.environ.get("AI_MODEL", "").strip()
AI_BASE_URL    = os.environ.get("AI_BASE_URL", "").strip()
AI_AUTO_ANALYSE = os.environ.get("AI_AUTO_ANALYSE", "true").strip().lower() == "true"


def is_configured() -> bool:
    return bool(AI_PROVIDER and AI_API_KEY)


def build_prompt(output: dict) -> str:
    sections = []

    if output.get("nmap"):
        sections.append("PORT SCAN RESULTS:\n" + json.dumps(output["nmap"], indent=2))
    if output.get("nse"):
        sections.append("NSE VULNERABILITY FINDINGS:\n" + json.dumps(output["nse"], indent=2))
    if output.get("nikto"):
        sections.append("WEB VULNERABILITY FINDINGS:\n" + json.dumps(output["nikto"], indent=2))

    scan_data = "\n\n".join(sections) if sections else "No scan data available."

    return f"""You are a network security analyst reviewing results from an internal vulnerability assessment tool. Analyse the following scan results and respond in this exact structure:

## Risk Level
One of: CRITICAL / HIGH / MEDIUM / LOW / INFO — choose the highest applicable level based on the findings.

## Summary
2-3 sentences describing what was found and the overall security posture of this host.

## Findings
For each significant finding, use this format:
**[SEVERITY] Finding title**
What it is, why it matters, and the specific evidence from the scan.

## Remediation Steps
A numbered list of concrete actions to take, ordered by priority. Be specific — include commands, configuration changes, or settings where relevant.

## Immediate Actions
If anything requires urgent attention, list it here. If nothing is urgent, write "No immediate actions required."

---

Be concise and practical. Write for a sysadmin audience, not executives. Do not repeat the raw scan data back.

SCAN RESULTS:
{scan_data}"""


def _call_groq(prompt: str) -> str:
    from groq import Groq
    client = Groq(api_key=AI_API_KEY)
    model = AI_MODEL or "llama-3.3-70b-versatile"
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500,
        temperature=0.3,
    )
    return response.choices[0].message.content


def _call_anthropic(prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=AI_API_KEY)
    model = AI_MODEL or "claude-sonnet-4-5"
    message = client.messages.create(
        model=model,
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


def _call_openai(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=AI_API_KEY)
    model = AI_MODEL or "gpt-4o-mini"
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500,
        temperature=0.3,
    )
    return response.choices[0].message.content


def _call_ollama(prompt: str) -> str:
    import requests
    base_url = AI_BASE_URL or "http://localhost:11434"
    model = AI_MODEL or "llama3"
    response = requests.post(
        f"{base_url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=120
    )
    response.raise_for_status()
    return response.json()["response"]


def analyse_scan(output: dict) -> str | None:
    """
    Takes a parsed scan result dict and returns an AI-generated
    remediation analysis string, or None if AI is not configured
    or the call fails.
    """
    if not is_configured():
        logger.debug("AI analysis skipped — not configured")
        return None

    try:
        prompt = build_prompt(output)

        if AI_PROVIDER == "groq":
            result = _call_groq(prompt)
        elif AI_PROVIDER == "anthropic":
            result = _call_anthropic(prompt)
        elif AI_PROVIDER == "openai":
            result = _call_openai(prompt)
        elif AI_PROVIDER == "ollama":
            result = _call_ollama(prompt)
        else:
            logger.warning(f"Unknown AI provider: {AI_PROVIDER}")
            return None

        logger.info(f"AI analysis complete ({AI_PROVIDER})")
        return result

    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None
