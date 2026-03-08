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
import logging
import os
from typing import Any, List

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from agent_framework.microsoft import PurviewPolicyMiddleware, PurviewSettings

# Route the Purview SDK's own logger to stdout with [PURVIEW_SDK] prefix.
# This surfaces debug, info, warning, and error messages from the SDK itself,
# including auth failures, pre-check/post-check errors, and block decisions.
_sdk_logger = logging.getLogger("agent_framework.purview")
if not _sdk_logger.handlers:
    _sdk_handler = logging.StreamHandler()
    _sdk_handler.setFormatter(logging.Formatter("[PURVIEW_SDK] %(levelname)s: %(message)s"))
    _sdk_logger.addHandler(_sdk_handler)
    _sdk_logger.setLevel(logging.DEBUG)
    _sdk_logger.propagate = False


def _build_purview_credential():
    """
    Prefer ClientSecretCredential using PURVIEW_* env vars so that Graph calls
    are made as the app registration that has InformationProtectionPolicy.Read.All
    (Application) granted.  Falls back to DefaultAzureCredential (ManagedIdentity
    on Azure, AzureCliCredential locally) when the secret is not configured.
    """
    tenant_id = os.environ.get("PURVIEW_TENANT_ID", "")
    client_id = os.environ.get("PURVIEW_CLIENT_APP_ID", "")
    client_secret = os.environ.get("PURVIEW_CLIENT_SECRET", "")
    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    _is_azure = bool(os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT"))
    return DefaultAzureCredential(exclude_managed_identity_credential=not _is_azure)


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
            credential=_build_purview_credential(),
            settings=PurviewSettings(
                app_name=app_name,
                blocked_prompt_message=(
                    "[PURVIEW BLOCKED] Your message contains sensitive information "
                    "that is restricted by your organisation's data loss prevention policy. "
                    "Please remove the sensitive content and try again."
                ),
                blocked_response_message=(
                    "[PURVIEW BLOCKED] The response contained sensitive information "
                    "that was redacted by your organisation's data loss prevention policy."
                ),
                # Log Purview errors but don't fail requests — allows local testing
                # while Graph API permissions (InformationProtectionPolicy.Read.All)
                # are being configured in Azure AD.
                ignore_exceptions=True,
            ),
        )
        middleware.append(purview)
        _log("purview_middleware_initialized", {"app_name": app_name})
    except Exception as exc:
        # Initialisation errors are logged but NOT fatal; the agent continues
        # without DLP rather than refusing to start.
        _log("purview_middleware_error", {"error": str(exc)})

    return middleware
