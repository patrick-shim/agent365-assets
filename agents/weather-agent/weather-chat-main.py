"""
agent_weather.py
================
A Microsoft 365 Agent (Bot Framework) that answers weather questions using
Azure OpenAI (GPT-4o / o-series) as its "brain" and the open-meteo.com APIs
for live weather data.

High-level request flow:
  1. Teams / M365 sends an HTTP POST to /api/messages
  2. CloudAdapter authenticates the request and deserialises the Activity
  3. on_message() is called with the user's text
  4. Azure AI Content Safety "Prompt Shields" scans the text for jailbreak attempts
  5. The Agent Framework calls Azure OpenAI; if the model decides weather data
     is needed it invokes the get_weather tool automatically
  6. The final text reply is sent back to the user via TurnContext.send_activity()

Dependencies (install via pip):
    aiohttp, azure-identity, requests, python-dotenv, pydantic
    microsoft-agents, microsoft-agents-a365, agent-framework (internal packages)

Environment variables (put in a .env file next to this file):
    AZURE_OPENAI_ENDPOINT                  – Azure OpenAI resource URL
    AZURE_OPENAI_CHAT_DEPLOYMENT_NAME      – e.g. "gpt-4o"
    AZURE_OPENAI_API_VERSION               – defaults to "2025-03-01-preview"
    AZURE_CONTENT_SAFETY_ENDPOINT          – optional: enables Prompt Shields
    BOT_APP_ID                             – Azure AD app registration client ID
    PORT                                   – HTTP port (default 8080)
    A365_TENANT_ID / A365_SERVICE_NAME / A365_SERVICE_NAMESPACE – observability
    AGENT_USER_ID                          – logical user label for audit logs
"""

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import json          # Used for serialising/deserialising JSON (logs, config files)
import os            # Used to read environment variables (secrets, config)
from pathlib import Path                   # Cross-platform file path handling
from typing import Annotated, Any, Dict, Optional  # Type hints for clarity and IDE support
from uuid import uuid4                     # Generates universally-unique IDs for correlation

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import requests                            # Synchronous HTTP client – used for REST API calls
from aiohttp import web                    # Async HTTP server framework – hosts the bot endpoint

# Azure Identity: provides credential objects that authenticate against Azure AD.
# DefaultAzureCredential tries multiple auth methods in order (env vars, managed identity,
# Azure CLI, etc.) so the same code works in local dev AND in production on Azure.
from azure.identity import DefaultAzureCredential

# Internal agent framework packages (Microsoft / Agent365):
# - Agent: orchestrates the LLM + tool-calling loop
# - tool: decorator that registers a Python function as a callable tool for the LLM
from agent_framework import Agent, tool

# Azure OpenAI client wrapper that integrates with the agent framework
from agent_framework.azure import AzureOpenAIResponsesClient

# python-dotenv: loads KEY=VALUE pairs from a .env file into os.environ at startup
from dotenv import load_dotenv

# Microsoft Agents SDK – Bot Framework successor for Python:
# - start_agent_process: wires an aiohttp Request into the bot pipeline
# - CloudAdapter: validates JWT tokens from the Bot Connector service
from microsoft_agents.hosting.aiohttp import start_agent_process, CloudAdapter

# Core abstractions for building bots/agents:
# - AgentApplication / ApplicationOptions: the main bot application container
# - MemoryStorage: in-process key-value store for conversation state (not persistent)
# - TurnContext: wraps the current Activity and provides send_activity()
# - TurnState: per-turn state bag passed to activity handlers
from microsoft_agents.hosting.core import (
    AgentApplication, ApplicationOptions, MemoryStorage, TurnContext, TurnState,
)

# Pydantic Field: used to attach human-readable descriptions to tool parameters.
# The LLM reads these descriptions to understand what each argument means.
from pydantic import Field
from defender import SecurityContext, shield_prompt, scan_output
from purview_dlp import build_security_middleware

# ---------------------------------------------------------------------------
# Load environment variables from .env BEFORE any Azure SDK calls, because
# DefaultAzureCredential reads AZURE_* vars from the environment.
# override=False means existing env vars (e.g. from a CI pipeline) take priority.
# ---------------------------------------------------------------------------
_ENV_FILE = Path(__file__).with_name(".env")
load_dotenv(dotenv_path=_ENV_FILE, override=False)

# ---------------------------------------------------------------------------
# Agent365 observability imports (OpenTelemetry-based tracing / metrics).
# These must be imported AFTER load_dotenv so the SDK can read config env vars.
# ---------------------------------------------------------------------------
# configure(): initialises the OpenTelemetry provider with a service name/namespace
from microsoft_agents_a365.observability.core.config import configure

# BaggageBuilder: attaches key-value "baggage" to the current trace span so that
# downstream services (and the Defender portal) can correlate requests.
from microsoft_agents_a365.observability.core.middleware.baggage_builder import BaggageBuilder

# AgentFrameworkInstrumentor: auto-instruments the agent framework with OTel spans,
# so every LLM call and tool invocation appears as a child span in the trace.
from microsoft_agents_a365.observability.extensions.agentframework.trace_instrumentor import (
    AgentFrameworkInstrumentor,
)


# ===========================================================================
# SECTION 2 – Configuration & Azure OpenAI Client Initialisation
# ===========================================================================

def _load_a365_config() -> Dict[str, Any]:
    """
    Loads optional Agent365 platform configuration from 'a365.config.json'
    (placed next to this file).

    This JSON file is typically generated by the Agent365 CLI / portal and
    contains metadata like tenant ID, agent blueprint name, and the Azure web
    app name. If the file does not exist (e.g. during local development) the
    function returns an empty dict and the code falls back to environment vars.

    Returns:
        A dict with Agent365 platform metadata, or {} if the file is absent.
    """
    cfg_path = Path(__file__).with_name("a365.config.json")
    if not cfg_path.exists():
        return {}
    return json.loads(cfg_path.read_text(encoding="utf-8"))


def _create_azure_openai_client() -> AzureOpenAIResponsesClient:
    """
    Constructs and returns an authenticated AzureOpenAIResponsesClient.

    The client wraps the Azure OpenAI REST API and is used by the Agent to
    send prompts and receive completions (including tool-call instructions).

    Configuration is read from environment variables so that the same code
    works across dev / staging / production by just changing env vars:
        AZURE_OPENAI_ENDPOINT              – e.g. https://my-resource.openai.azure.com
        AZURE_OPENAI_CHAT_DEPLOYMENT_NAME  – deployment name (e.g. "gpt-4o")
        AZURE_OPENAI_API_VERSION           – defaults to "2025-03-01-preview"

    Raises:
        RuntimeError – if any required environment variable is missing, so
                       the app fails immediately at startup with a clear message
                       rather than with a cryptic auth error at request time.
    """
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")

    # Support two env var names for the deployment – allows gradual migration
    deployment_name = os.environ.get("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME") or os.environ.get(
        "AZURE_OPENAI_DEPLOYMENT_NAME"
    )
    # Use a recent stable preview API version if one is not explicitly configured
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION") or "2025-03-01-preview"

    # Collect the names of any missing required variables for a helpful error message
    missing = [
        name
        for name, val in [
            ("AZURE_OPENAI_ENDPOINT", endpoint),
            ("AZURE_OPENAI_CHAT_DEPLOYMENT_NAME", deployment_name),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variables for Azure OpenAI: " + ", ".join(missing)
        )

    return AzureOpenAIResponsesClient(
        endpoint=endpoint or "",
        deployment_name=deployment_name or "",
        api_version=api_version,
        # DefaultAzureCredential handles auth transparently in all environments
        credential=DefaultAzureCredential(),
    )


# ===========================================================================
# SECTION 3 – Utility Helpers
# ===========================================================================

def _http_get_json(url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Makes a synchronous HTTP GET request and returns the parsed JSON body as a dict.

    This small wrapper exists so that the weather tool can call public REST APIs
    without repeating error-handling boilerplate at every call site.

    Parameters:
        url    – The full URL to request.
        params – Optional dict of query-string parameters (e.g. {"name": "Seoul"}).

    Returns:
        The response body parsed as a Python dict.

    Raises:
        requests.HTTPError – for 4xx / 5xx responses (via raise_for_status).
        RuntimeError       – if the response body is not a JSON object (dict).
    """
    resp = requests.get(url, params=params, timeout=20)
    resp.raise_for_status()   # Raise on HTTP error codes
    data = resp.json()
    if not isinstance(data, dict):
        # Defensive check – some APIs return a list at the top level
        raise RuntimeError(f"Unexpected JSON payload from {url}: {data}")
    return data


# ===========================================================================
# SECTION 4 – Weather Tool (callable by the LLM)
# ===========================================================================

@tool(approval_mode="never_require")
# The @tool decorator registers this function with the Agent Framework so that
# the LLM can choose to call it.  approval_mode="never_require" means the
# framework executes the tool automatically without asking the user to confirm
# each invocation (appropriate for read-only, low-risk operations like weather).
def get_weather(
    # Annotated[type, Field(...)] lets us attach a description that the LLM
    # reads to understand what value to pass for each argument.
    location: Annotated[str, Field(description="City or place name, e.g. 'Seoul' or 'Seattle'.")],
    units: Annotated[
        str,
        Field(
            description="Units for temperature. Use 'c' for Celsius, 'f' for Fahrenheit.",
        ),
    ] = "c",   # Default to Celsius; the LLM can override based on the user's preference
    **_: Any,  # Absorb any extra kwargs the framework might inject (future-proofing)
) -> str:
    """
    Fetches current weather for a location using two free, public APIs:
        1. open-meteo Geocoding API – converts a place name to lat/lon coordinates.
        2. open-meteo Forecast API  – fetches the current temperature and wind speed.

    The function is intentionally self-contained: it does its own HTTP calls
    rather than using a weather SDK so there are no additional dependencies.

    Parameters:
        location – Human-readable city or place name (passed by the LLM).
        units    – 'c' for Celsius (default) or 'f' for Fahrenheit.

    Returns:
        A single human-readable sentence describing the current weather,
        or an error sentence if the location cannot be found or data is missing.
        The LLM will relay this string directly to the user.
    """
    # ---- Step 1: Geocode the place name to (latitude, longitude) ----
    geocode = _http_get_json(
        "https://geocoding-api.open-meteo.com/v1/search",
        params={
            "name": location,    # The place name to look up
            "count": 1,          # We only need the best match
            "language": "en",    # Return place names in English
            "format": "json",
        },
    )
    results = geocode.get("results") or []  # "results" key holds the list of matches
    if not results:
        # Return a friendly error string; the LLM will tell the user naturally
        return f"I couldn't find coordinates for '{location}'."

    # Extract metadata from the first (best) geocoding result
    place = results[0]
    lat = place.get("latitude")
    lon = place.get("longitude")
    name = place.get("name")        # Canonical place name (may differ from user input)
    country = place.get("country")  # Country name for disambiguation (e.g. "Seoul, South Korea")

    if lat is None or lon is None:
        return f"I couldn't find coordinates for '{location}'."

    # ---- Step 2: Convert units flag to the string the Forecast API expects ----
    temperature_unit = "fahrenheit" if units.lower().startswith("f") else "celsius"

    # ---- Step 3: Fetch current weather from the Forecast API ----
    weather = _http_get_json(
        "https://api.open-meteo.com/v1/forecast",
        params={
            "latitude": lat,
            "longitude": lon,
            # "current" selects which variables to include in the "current" response block
            "current": "temperature_2m,wind_speed_10m",
            "temperature_unit": temperature_unit,
        },
    )

    # ---- Step 4: Extract values from the nested response structure ----
    current = weather.get("current") or {}
    temp = current.get("temperature_2m")   # Temperature at 2 m above ground
    wind = current.get("wind_speed_10m")   # Wind speed at 10 m above ground, in km/h

    # Choose the correct unit symbol for the response string
    unit_symbol = "°F" if temperature_unit == "fahrenheit" else "°C"

    # Build a readable place label, skipping None parts (e.g. if country is missing)
    place_label = ", ".join([p for p in [name, country] if p])

    # ---- Step 5: Build and return the human-readable weather string ----
    if temp is None:
        return f"I couldn't fetch current temperature for {place_label or location}."
    if wind is None:
        # Wind data missing – still return the temperature (partial success)
        return f"Current temperature in {place_label or location} is {temp}{unit_symbol}."

    return (
        f"Current weather in {place_label or location}: {temp}{unit_symbol}, wind {wind} km/h."
    )


# ===========================================================================
# SECTION 5 – Observability / Tracing Initialisation
# ===========================================================================

def _enable_observability(a365_config: Dict[str, Any]) -> None:
    """
    Initialises the OpenTelemetry (OTel) tracing and metrics pipeline.

    What this does:
        - configure() sets up the OTel SDK with a TracerProvider that exports
          spans to Azure Monitor (Application Insights) using the service name
          and namespace as resource attributes. This lets you filter traces in
          the Azure portal by service.
        - AgentFrameworkInstrumentor().instrument() monkey-patches the agent
          framework so every LLM call and tool invocation automatically creates
          a child span, giving full end-to-end visibility without manual
          instrumentation in application code.

    Service name/namespace precedence:
        1. Environment variable (A365_SERVICE_NAME / A365_SERVICE_NAMESPACE)
        2. Hardcoded defaults below (used for local development)

    Parameters:
        a365_config – The dict loaded from a365.config.json (may be empty).
    """
    # Service name appears as the "cloud_RoleName" dimension in Application Insights
    service_name = os.environ.get("A365_SERVICE_NAME") or "agent365-simple-weather"
    service_namespace = os.environ.get("A365_SERVICE_NAMESPACE") or "agent365-demo"

    # Initialise the OTel SDK with the service identity
    configure(service_name=service_name, service_namespace=service_namespace)

    # Auto-instrument the agent framework – no code changes needed in tools or handlers
    AgentFrameworkInstrumentor().instrument()


# ===========================================================================
# SECTION 6 – Module-level Initialisation (runs once at process startup)
# ===========================================================================

# Load optional Agent365 platform config (tenant ID, agent blueprint name, etc.)
_a365_config = _load_a365_config()

# Start the OTel tracing pipeline BEFORE creating any Azure SDK objects, so
# the SDK constructors are also captured in traces.
_enable_observability(_a365_config)

# Resolve the tenant ID using a priority chain:
#   1. a365.config.json  →  2. env var  →  3. fallback "unknown"
_tenant_id: str = (
    _a365_config.get("tenantId") or os.environ.get("A365_TENANT_ID") or "unknown"
)

# Resolve a human-readable agent identifier for log records
_agent_id: str = (
    _a365_config.get("webAppName")                    # Azure Web App name (preferred)
    or _a365_config.get("agentBlueprintDisplayName")  # Agent365 display name
    or os.environ.get("A365_AGENT_ID")                # Override via env var
    or "simple-agent"                                  # Local development fallback
)

# Create the SecurityContext singleton.
# correlation_id is regenerated every time the process starts (not per-turn),
# so it correlates all turns within a single server lifetime.
_sec_ctx = SecurityContext(
    tenant_id=str(_tenant_id),
    user_id=os.environ.get("AGENT_USER_ID", "demo-user"),  # Logical user label
    correlation_id=str(uuid4()),  # Unique ID for this process lifetime
)

# Create the Azure OpenAI client (validates required env vars; raises early if missing)
_openai_client = _create_azure_openai_client()

# Create the Agent – the core LLM orchestrator.
# - instructions: the system prompt that shapes the model's behaviour and persona.
# - tools: the list of Python functions the model is allowed to call.
#   When the model decides to check the weather it emits a tool_call; the
#   framework invokes get_weather() and feeds the result back to the model.
_ai_agent = Agent(
    client=_openai_client,
    instructions=(
        "You are a helpful Agent 365 demo assistant. "
        "If the user asks about weather, call the get_weather tool. "
        "Be concise."
    ),
    tools=[get_weather],  # Only one tool registered; extend this list to add capabilities
    middleware=build_security_middleware(),  # Purview DLP (no-op if not configured)
)


# ===========================================================================
# SECTION 7 – Microsoft 365 Agent Application & Message Handler
# ===========================================================================

# CloudAdapter handles the Bot Framework authentication handshake:
# it verifies the JWT token on incoming requests and signs outgoing replies.
_cloud_adapter = CloudAdapter()

# AgentApplication is the top-level bot container.
# ApplicationOptions wires together the adapter, storage, and bot app ID.
# MemoryStorage stores conversation state in memory (lost on restart – fine for demos).
# For production, replace MemoryStorage with a database-backed storage provider.
AGENT_APP = AgentApplication(
    ApplicationOptions(
        adapter=_cloud_adapter,
        storage=MemoryStorage(),
        # BOT_APP_ID must match the Azure AD app registration for the bot.
        # An empty string works for local testing with the Bot Framework Emulator.
        bot_app_id=os.environ.get("BOT_APP_ID", ""),
    )
)


@AGENT_APP.activity("message")
# This decorator registers on_message as the handler for Activity type "message".
# Other activity types (typing, reaction, etc.) are ignored by default.
async def on_message(context: TurnContext, _: TurnState) -> None:
    """
    Entry point for every user message.

    Called by the AgentApplication once per incoming "message" Activity.

    Parameters:
        context – Wraps the current Activity; use context.send_activity() to reply.
        _       – TurnState (not used here, but required by the handler signature).

    Flow:
        1. Extract and clean the user's text.
        2. Run Prompt Shield security scan.
        3. If safe, run the AI agent (with OTel baggage attached to the span).
        4. Send the agent's text response back to the user.
    """
    # Extract the user's message text and strip leading/trailing whitespace.
    # activity.text can be None if the Activity is non-text (e.g. a card action),
    # so we guard with an empty-string default.
    user_text = (context.activity.text or "").strip()
    if not user_text:
        # Nothing to process (e.g. empty message or attachment-only activity)
        return

    # ---- Security gate: scan for jailbreak / prompt injection ----
    shield_block = shield_prompt(user_text, _sec_ctx)
    if shield_block:
        # The prompt was flagged – send the refusal message and stop processing.
        # We do NOT pass the text to the LLM at all.
        await context.send_activity(shield_block)
        return

    # ---- Run the AI agent inside an OTel baggage context ----
    # BaggageBuilder adds key-value metadata to the current trace span.
    # All downstream calls (OpenAI, tool invocations) inherit this baggage,
    # making it easy to correlate a single user turn across microservices.
    with (
        BaggageBuilder()
        .tenant_id(str(_tenant_id))          # Which tenant this request belongs to
        .agent_id(str(_agent_id))            # Which agent blueprint is handling it
        .correlation_id(str(uuid4()))        # Fresh UUID per turn for fine-grained tracing
        .build()
    ):
        # _ai_agent.run() sends user_text to Azure OpenAI.
        # If the model issues a tool call (e.g. get_weather), the framework
        # executes it automatically and sends the result back in a second LLM call.
        # The returned result object holds the final assistant reply.
        result = await _ai_agent.run(user_text)

    # Extract the text from the result object.
    # The agent framework may return different result types; .text is the
    # standard attribute, but we fall back to str() for compatibility.
    text = getattr(result, "text", None)
    if text is None:
        text = str(result)

    # POST-LLM output scan (Defender AI gate — mirrors pre-LLM Prompt Shields)
    output_block = scan_output(text)
    if output_block:
        await context.send_activity(output_block)
        return

    # Send the final response back to the Teams / M365 channel
    await context.send_activity(text)


# ===========================================================================
# SECTION 8 – aiohttp Web Server
# ===========================================================================

async def _handle_messages(request: web.Request) -> web.Response:
    """
    aiohttp request handler for POST /api/messages.

    This is the single HTTP endpoint that Microsoft's Bot Connector service
    (and the Bot Framework Emulator) POSTs incoming Activities to.

    start_agent_process() deserialises the JSON body into an Activity object,
    authenticates the request via CloudAdapter, and dispatches it to AGENT_APP
    which calls on_message() for "message" activities.

    Parameters:
        request – The raw aiohttp Request object.

    Returns:
        The web.Response produced by start_agent_process, or a plain 200 OK
        if start_agent_process returns None (e.g. for proactive messages).
    """
    response = await start_agent_process(request, AGENT_APP, _cloud_adapter)
    # Return 200 OK even if no response was generated (e.g. for activity types we ignore)
    return response or web.Response(status=200)


def main() -> None:
    """
    Application entry point.

    Sets up the aiohttp web server and starts the event loop.
    The server listens on 0.0.0.0 (all interfaces) so it is reachable inside
    Docker containers and Azure App Service environments.

    Port precedence: PORT env var → 8080 default.
    """
    port = int(os.environ.get("PORT", 8080))

    # Create an aiohttp Application and register our single route
    http_app = web.Application()
    http_app.router.add_post("/api/messages", _handle_messages)

    print(f"Agent 365 weather agent listening on port {port}")

    # web.run_app() starts the asyncio event loop and blocks until the process
    # receives a shutdown signal (Ctrl+C / SIGTERM).
    web.run_app(http_app, host="0.0.0.0", port=port)


# ---------------------------------------------------------------------------
# Allow the module to be run directly with: python agent_weather.py
# When imported as a module (e.g. by a test suite) main() is NOT called.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()