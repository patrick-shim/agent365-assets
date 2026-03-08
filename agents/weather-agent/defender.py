"""
defender.py
===========
Azure AI Defender security helpers for the Agent 365 weather agent.

Provides two symmetric security gates around the LLM:

  1. Pre-LLM  gate — shield_prompt()
     Calls Azure AI Content Safety "Prompt Shields" to detect jailbreak and
     prompt-injection attacks BEFORE the user's text is sent to the LLM.

  2. Post-LLM gate — scan_output()
     Calls Azure AI Content Safety "text:analyze" to detect harmful content
     (Hate, Violence, Sexual, Self-harm) in the LLM's reply BEFORE it is
     delivered to the user.

Full security pipeline in weather-chat-main.py:
    User text
      → [shield_prompt]          pre-LLM input gate  (this module)
      → [PurviewPolicyMiddleware] in-Agent DLP gate   (purview_dlp.py)
      → LLM
      → [scan_output]            post-LLM output gate (this module)
      → User

Both gates use DefaultAzureCredential and gracefully skip when
AZURE_CONTENT_SAFETY_ENDPOINT is not set (local dev without Content Safety).

Environment variables:
    AZURE_CONTENT_SAFETY_ENDPOINT  – Azure AI Content Safety / Azure OpenAI
                                     resource URL.  Required for both gates.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests
from azure.identity import DefaultAzureCredential


# ===========================================================================
# Security context
# ===========================================================================

@dataclass
class SecurityContext:
    """
    Carries security metadata for a single logical session.

    A single instance is created at process startup and reused across turns.

    Attributes:
        tenant_id          – Azure AD tenant that owns this bot deployment.
        user_id            – Logical identifier for the calling user (audit logs).
        correlation_id     – UUID linking all log records for this server lifetime.
        jailbreak_attempts – Running count of Prompt Shield blocks; use for
                             rate-limiting or escalating repeat offenders.
    """
    tenant_id: str
    user_id: str
    correlation_id: str
    jailbreak_attempts: int = 0


# ===========================================================================
# Internal helpers
# ===========================================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_security_event(event: str, ctx: SecurityContext, details: dict) -> None:
    """
    Emits a structured JSON security event to stdout.

    Records are tagged with layer "DEFENDER_AI" for easy filtering in
    Azure Monitor, Microsoft Defender for Cloud, and log aggregators.
    """
    record = {
        "time": _utc_now(),
        "event": event,
        "layer": "DEFENDER_AI",
        "correlation_id": ctx.correlation_id,
        "tenant_id": ctx.tenant_id,
        "user_id": ctx.user_id,
        "jailbreak_attempts": ctx.jailbreak_attempts,
        "details": details,
    }
    print(f"[DEFENDER_AI] {event}: {json.dumps(record, ensure_ascii=False)}")


def _get_content_safety_token() -> str:
    return DefaultAzureCredential().get_token(
        "https://cognitiveservices.azure.com/.default"
    ).token


# ===========================================================================
# Gate 1 — Pre-LLM: Prompt Shields
# ===========================================================================

def shield_prompt(user_text: str, ctx: SecurityContext) -> Optional[str]:
    """
    Pre-LLM security gate.

    Calls the Azure AI Content Safety "shieldPrompt" endpoint to detect
    jailbreak and prompt-injection attacks before the text reaches the LLM.

    Parameters:
        user_text – Raw user input to scan.
        ctx       – SecurityContext; jailbreak_attempts is incremented on block.

    Returns:
        A refusal string if an attack is detected, or None if the text is safe
        (or if scanning is skipped because the endpoint is not configured).
    """
    cs_endpoint = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT", "").rstrip("/")
    if not cs_endpoint:
        return None

    url = f"{cs_endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01"
    try:
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {_get_content_safety_token()}",
                "Content-Type": "application/json",
            },
            json={"userPrompt": user_text, "documents": []},
            timeout=10,
        )
        resp.raise_for_status()
        result = resp.json()

        attack = result.get("userPromptAnalysis", {}).get("attackDetected", False)
        log_security_event("prompt_shield_scanned", ctx, {
            "attack_detected": attack,
            "raw": result,
        })

        if attack:
            ctx.jailbreak_attempts += 1
            log_security_event("prompt_shield_blocked", ctx, {
                "jailbreak_attempts": ctx.jailbreak_attempts,
            })
            return "Request blocked: prompt injection or jailbreak attempt detected."

    except Exception as exc:
        log_security_event("prompt_shield_error", ctx, {"error": str(exc)})

    return None


# ===========================================================================
# Gate 2 — Post-LLM: Output Content Scanner
# ===========================================================================

def scan_output(text: str, severity_threshold: int = 2) -> Optional[str]:
    """
    Post-LLM security gate.

    Calls the Azure AI Content Safety "text:analyze" endpoint to detect
    harmful content in the LLM's reply before it is sent to the user.

    Severity scale (Content Safety API):
        0 = Safe   2 = Low   4 = Medium   6 = High
    severity_threshold (default 2) blocks anything above Safe.
    Raise to 4 to allow Low-severity content through.

    Parameters:
        text               – LLM output string to evaluate.
        severity_threshold – Minimum severity level that triggers a block.

    Returns:
        A refusal string if harmful content is detected, or None if the output
        is safe (or if scanning is skipped because the endpoint is not set).
    """
    cs_endpoint = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT", "").rstrip("/")
    if not cs_endpoint:
        return None

    url = f"{cs_endpoint}/contentsafety/text:analyze?api-version=2024-09-01"
    try:
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {_get_content_safety_token()}",
                "Content-Type": "application/json",
            },
            json={
                "text": text,
                "categories": ["Hate", "Violence", "Sexual", "SelfHarm"],
                "outputType": "FourSeverityLevels",
            },
            timeout=10,
        )
        resp.raise_for_status()
        result = resp.json()

        categories = result.get("categoriesAnalysis", [])
        violations = [c for c in categories if c.get("severity", 0) >= severity_threshold]

        print(f"[DEFENDER_AI] output_scan_complete: {json.dumps({'text_length': len(text), 'violations': violations}, ensure_ascii=False)}")

        if violations:
            flagged = ", ".join(c["category"] for c in violations)
            return f"Response blocked: output safety check failed ({flagged})."

    except Exception as exc:
        print(f"[DEFENDER_AI] output_scan_error: {json.dumps({'error': str(exc)}, ensure_ascii=False)}")

    return None
