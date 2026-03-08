"""
weather-chat-client.py
======================
Interactive local test client for the weather agent.

Bypasses the full Bot Framework stack and talks directly to the Agent
Framework, so you can test the LLM + weather tool without needing the
Bot Framework Emulator or a deployed Azure service.

Usage:
    python weather-chat-client.py
    python weather-chat-client.py "What's the weather in Seoul?"

Loads .local.env by default (falls back to .env if not found).
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import requests
from agent_framework import Agent, tool
from agent_framework.azure import AzureOpenAIResponsesClient
from azure.identity import DefaultAzureCredential
from dotenv import load_dotenv
from pydantic import Field
from purview_dlp import build_security_middleware


# ---------------------------------------------------------------------------
# Load environment
# ---------------------------------------------------------------------------

_here = Path(__file__).parent
_local_env = _here / ".local.env"
_env       = _here / ".env"

if _local_env.exists():
    load_dotenv(_local_env, override=True)
    print(f"[client] Loaded {_local_env.name}")
else:
    load_dotenv(_env, override=True)
    print(f"[client] Loaded {_env.name}")


# ---------------------------------------------------------------------------
# Weather tool (copy from weather-chat-main.py — kept local to avoid
# importing the full bot framework initialisation)
# ---------------------------------------------------------------------------

def _http_get(url: str, params: dict) -> dict:
    resp = requests.get(url, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


@tool(approval_mode="never_require")
def get_weather(
    location: Annotated[str, Field(description="City or place name.")],
    units: Annotated[str, Field(description="'c' for Celsius, 'f' for Fahrenheit.")] = "c",
    **_: Any,
) -> str:
    geocode = _http_get(
        "https://geocoding-api.open-meteo.com/v1/search",
        {"name": location, "count": 1, "language": "en", "format": "json"},
    )
    results = geocode.get("results") or []
    if not results:
        return f"Couldn't find '{location}'."

    place   = results[0]
    lat, lon = place.get("latitude"), place.get("longitude")
    name    = place.get("name")
    country = place.get("country")

    if lat is None or lon is None:
        return f"Couldn't find coordinates for '{location}'."

    unit_str = "fahrenheit" if units.lower().startswith("f") else "celsius"
    weather  = _http_get(
        "https://api.open-meteo.com/v1/forecast",
        {"latitude": lat, "longitude": lon,
         "current": "temperature_2m,wind_speed_10m",
         "temperature_unit": unit_str},
    )
    current  = weather.get("current") or {}
    temp     = current.get("temperature_2m")
    wind     = current.get("wind_speed_10m")
    sym      = "°F" if unit_str == "fahrenheit" else "°C"
    label    = ", ".join(p for p in [name, country] if p)

    if temp is None:
        return f"Couldn't fetch temperature for {label or location}."
    return f"Current weather in {label or location}: {temp}{sym}, wind {wind} km/h."


# ---------------------------------------------------------------------------
# Build agent
# ---------------------------------------------------------------------------

def _build_agent() -> Agent:
    endpoint   = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    deployment = os.environ.get("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME", "")
    api_ver    = os.environ.get("AZURE_OPENAI_API_VERSION", "")

    if not endpoint or not deployment:
        print("[client] ERROR: AZURE_OPENAI_ENDPOINT and "
              "AZURE_OPENAI_CHAT_DEPLOYMENT_NAME must be set.")
        sys.exit(1)

    client = AzureOpenAIResponsesClient(
        endpoint=endpoint,
        deployment_name=deployment,
        api_version=api_ver,
        credential=DefaultAzureCredential(),
    )
    return Agent(
        client=client,
        instructions=(
            "You are a helpful weather assistant. "
            "When asked about weather, call the get_weather tool. "
            "Be concise."
        ),
        tools=[get_weather],
        middleware=build_security_middleware(),
    )


# ---------------------------------------------------------------------------
# Interactive loop
# ---------------------------------------------------------------------------

async def _chat(agent: Agent, message: str) -> str:
    result = await agent.run(message)
    return getattr(result, "text", None) or str(result)


async def _run_client() -> None:
    agent = _build_agent()
    print("[client] Agent ready. Type 'exit' to quit.\n")

    # One-shot mode: python weather-chat-client.py "What's the weather in Seoul?"
    if len(sys.argv) > 1:
        query  = " ".join(sys.argv[1:])
        print(f"You: {query}")
        reply  = await _chat(agent, query)
        print(f"Bot: {reply}")
        return

    # Interactive mode
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[client] Bye!")
            break

        if not user_input or user_input.lower() in {"exit", "quit", "bye"}:
            print("[client] Bye!")
            break

        reply = await _chat(agent, user_input)
        print(f"Bot: {reply}\n")


if __name__ == "__main__":
    asyncio.run(_run_client())
