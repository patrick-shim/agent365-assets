"""
purview_dlp.py
==============
Security middleware helpers for the Agent 365 weather agent.

Provides two additional protection layers beyond the pre-LLM Prompt Shields
already in simple-chat.py:

  1. Microsoft Purview DLP  (PurviewPolicyMiddleware)
     Enforces your organisation's Purview information-protection policies at the
     Agent Framework level.  Blocks sensitive data — SSN, credit-card numbers,
     custom classification labels, etc. — from appearing in prompts OR in LLM
     responses, according to the policies you have configured in the Microsoft
     Purview compliance portal.
     Requires env var: PURVIEW_CLIENT_APP_ID

  2. Azure AI Content Safety — Output Scanner  (post-LLM Defender gate)
     Calls the Azure AI Content Safety "text:analyze" REST endpoint to check
     the LLM's final reply for harmful content (Hate, Violence, Sexual,
     Self-harm) BEFORE it is delivered to the user.
     This makes the safety pipeline symmetric:
         User text  →  [Prompt Shields, pre-LLM]  →  LLM
                    →  [Output Scanner, post-LLM]  →  User
     Requires env var: AZURE_CONTENT_SAFETY_ENDPOINT (shared with Prompt Shields)

Usage in simple-chat.py  (three lines of change):
    from purview_dlp import build_security_middleware, scan_output

    _ai_agent = Agent(..., middleware=build_security_middleware())

    # after _ai_agent.run(), before context.send_activity():
    block = scan_output(text)
    if block:
        await context.send_activity(block); return
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, List, Optional

import requests
from azure.identity import DefaultAzureCredential
from agent_framework.microsoft import PurviewPolicyMiddleware, PurviewSettings


# ---------------------------------------------------------------------------
# Internal logging helper  (mirrors the pattern used in simple-chat.py)
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(event: str, details: dict) -> None:
    record = {"time": _utc_now(), "event": event, "layer": "SECURITY_MIDDLEWARE", **details}
    print(f"[SECURITY] {event}: {json.dumps(record, ensure_ascii=False)}")


# ===========================================================================
# 1 – Microsoft Purview DLP Middleware
# ===========================================================================

def build_security_middleware() -> List[Any]:
    """
    Builds and returns the Agent Framework middleware list for the agent.

    Currently wires in PurviewPolicyMiddleware when PURVIEW_CLIENT_APP_ID is
    present in the environment.  Returns an empty list otherwise so the agent
    runs normally in local development without a Purview tenant.

    The returned list is passed directly to Agent(middleware=[...]).

    Environment variables:
        PURVIEW_CLIENT_APP_ID  – App registration ID for your Purview client app.
                                 If absent, Purview middleware is skipped entirely.
        PURVIEW_APP_NAME       – Friendly name shown in the Purview audit trail
                                 (default: "Agent365 Weather Agent").

    Returns:
        List of middleware instances (may be empty).
    """
    middleware: List[Any] = []

    client_app_id = os.environ.get("PURVIEW_CLIENT_APP_ID", "")
    if not client_app_id:
        _log("purview_skipped", {"reason": "PURVIEW_CLIENT_APP_ID not configured"})
        return middleware

    app_name = os.environ.get("PURVIEW_APP_NAME", "Agent365 Weather Agent")

    try:
        purview = PurviewPolicyMiddleware(
            # DefaultAzureCredential resolves to Managed Identity on Azure App Service
            # and to 'az login' / env vars in local development — no secrets in code.
            credential=DefaultAzureCredential(),
            settings=PurviewSettings(app_name=app_name),
        )
        middleware.append(purview)
        _log("purview_middleware_initialized", {"app_name": app_name})
    except Exception as exc:
        # Initialisation errors are logged but NOT fatal; the agent continues
        # without DLP rather than refusing to start.
        _log("purview_middleware_error", {"error": str(exc)})

    return middleware


# ===========================================================================
# 2 – Azure AI Content Safety — Output Scanner (post-LLM Defender gate)
# ===========================================================================

def scan_output(text: str, severity_threshold: int = 2) -> Optional[str]:
    """
    Scans the LLM's response text for harmful content via Azure AI Content Safety.

    This is the POST-LLM output gate.  It mirrors _shield_prompt() in
    simple-chat.py which is the PRE-LLM input gate.  Together they form a
    defence-in-depth pipeline:

        User  →  Prompt Shields (input)  →  LLM  →  Output Scanner  →  User

    Severity scale (Content Safety API):
        0 = Safe   2 = Low   4 = Medium   6 = High
    severity_threshold (default 2) blocks anything above "safe".

    Parameters:
        text               – The LLM's final reply string to evaluate.
        severity_threshold – Minimum severity level that triggers a block (0-6).
                             Increase to 4 to allow "Low" severity content through.

    Returns:
        A refusal string to send to the user if harmful content is detected, or
        None if the output is safe (or if scanning is skipped because
        AZURE_CONTENT_SAFETY_ENDPOINT is not set).
    """
    cs_endpoint = os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT", "").rstrip("/")
    if not cs_endpoint:
        return None

    url = f"{cs_endpoint}/contentsafety/text:analyze?api-version=2024-09-01"
    try:
        token = DefaultAzureCredential().get_token(
            "https://cognitiveservices.azure.com/.default"
        ).token

        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
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

        _log("output_scan_complete", {
            "text_length": len(text),
            "categories": categories,
            "violations": violations,
        })

        if violations:
            flagged = ", ".join(c["category"] for c in violations)
            return f"Response blocked: output safety check failed ({flagged})."

    except Exception as exc:
        _log("output_scan_error", {"error": str(exc)})

    return None
