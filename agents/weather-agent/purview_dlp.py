"""
purview_dlp.py
==============
Microsoft Purview DLP middleware for the Agent 365 weather agent.

Enforces your organisation's Purview information-protection policies at the
Agent Framework level.  Blocks sensitive data — SSN, credit-card numbers,
custom classification labels, etc. — from appearing in prompts OR in LLM
responses, according to the policies configured in the Microsoft Purview
compliance portal.

The Defender AI security gates (shield_prompt, scan_output) live in defender.py.

Usage in weather-chat-main.py:
    from purview_dlp import build_security_middleware

    _ai_agent = Agent(..., middleware=build_security_middleware())

Requires env var: PURVIEW_CLIENT_APP_ID  (leave blank to disable)
"""

import json
import os
from typing import Any, List

from azure.identity import DefaultAzureCredential
from agent_framework.microsoft import PurviewPolicyMiddleware, PurviewSettings


def _log(event: str, details: dict) -> None:
    print(f"[PURVIEW] {event}: {json.dumps(details, ensure_ascii=False)}")


# ===========================================================================
# Microsoft Purview DLP Middleware
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
