# Agent 365 Simple Weather Agent

A Microsoft Teams-integrated AI agent built with the **Agent Framework** and hosted on **Microsoft Agent 365**. It answers weather queries using a live weather API and protects every turn with **Microsoft Defender AI Prompt Shields** to detect and block prompt injection and jailbreak attempts.

---

## Purpose

| Capability | Detail |
|---|---|
| **Conversational AI** | Powered by Azure OpenAI (Responses API) via `agent-framework` |
| **Weather tool** | Real-time temperature and wind data from Open-Meteo (no API key required) |
| **Defender AI** | Every user message is scanned by Azure AI Content Safety Prompt Shields before reaching the LLM |
| **Teams integration** | Runs as a Bot Framework–compatible `aiohttp` web server; deployed to Azure App Service and published to Microsoft Teams via Agent 365 |
| **Observability** | Full OpenTelemetry tracing via `microsoft-agents-a365-observability` SDK |

---

## Architecture

```
Microsoft Teams
      │  Bot Framework Activity (POST /api/messages)
      ▼
Azure App Service  ──  simple-chat.py  (aiohttp web server, port 8080)
      │
      ├─ CloudAdapter  (Bot Framework auth & protocol)
      │
      └─ AgentApplication
              │
              ▼
        on_message handler
              │
              ├─ [1] Defender AI Prompt Shields
              │       └─ Azure AI Content Safety REST API
              │              → blocked?  reply + stop
              │
              ├─ [2] A365 Observability BaggageBuilder
              │       └─ injects tenant_id / agent_id / correlation_id into trace
              │
              └─ [3] agent-framework Agent
                      ├─ AzureOpenAIResponsesClient  (GPT model)
                      └─ get_weather tool
                              ├─ Open-Meteo Geocoding API
                              └─ Open-Meteo Forecast API
```

---

## Flow Diagram

```
User (Teams)
    │
    │  "What's the weather in Seoul?"
    ▼
POST https://<webapp>.azurewebsites.net/api/messages
    │
    ▼
CloudAdapter  ── validates Bot Framework JWT token
    │
    ▼
on_message(TurnContext)
    │
    ├──► _shield_prompt()
    │         │
    │         ├─ GET Azure CLI / Managed Identity token
    │         ├─ POST /contentsafety/text:shieldPrompt
    │         │
    │         ├─ attackDetected = false  ──► continue ──────────────────────┐
    │         └─ attackDetected = true   ──► reply "Request blocked" + stop │
    │                                                                        │
    ▼                                                                        │
BaggageBuilder (tenant_id, agent_id, correlation_id)  ◄─────────────────────┘
    │
    ▼
agent.run(user_text)
    │
    ├─ LLM decides to call get_weather("Seoul")
    │       └─ Open-Meteo API → "Seoul, South Korea: 12°C, wind 8 km/h"
    │
    └─ LLM composes final reply
            │
            ▼
context.send_activity("Current weather in Seoul …")
            │
            ▼
        Teams chat
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | App Service runtime is PYTHON\|3.11 |
| Azure CLI (`az`) | Must be logged in with `az login` |
| PowerShell + `Microsoft.Graph.*` modules | Required by `a365` CLI |
| `uv` package manager | Required by `a365 deploy` — install via `winget install astral-sh.uv` |
| Azure subscription | Contributor or Owner role |
| **Global Administrator** account | Required for `a365 setup blueprint` and `a365 setup permissions` |
| **Frontier Preview Program** enrollment | Required for Agent 365; enroll at https://adoption.microsoft.com/copilot/frontier-program/ |

> **Windows note**: `a365` CLI commands that require interactive auth (WAM) **must be run from a standalone PowerShell window**, not the VS Code integrated terminal.

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values:

```env
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com/
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=<your-deployment-name>
AZURE_OPENAI_API_VERSION=2025-03-01-preview

# Defender AI – Prompt Shields (can be the same Cognitive Services endpoint)
AZURE_CONTENT_SAFETY_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com/

# Teams bot identity (filled automatically by `a365 setup blueprint`)
BOT_APP_ID=<blueprint-app-id>
PORT=8080

# Observability
ENABLE_A365_OBSERVABILITY_EXPORTER=false   # true = send to A365 portal; false = console
A365_SERVICE_NAME=agent365-simple-weather
A365_SERVICE_NAMESPACE=agent365-demo
```

The `CONNECTIONS__*`, `AGENTAPPLICATION__*`, and `CONNECTIONSMAP__*` variables are **stamped automatically** by `a365 setup blueprint` — do not set these manually.

> **Security**: Never commit `.env` or `a365.generated.config.json` to source control. Both are already in `.gitignore`.

---

## Local Setup

```powershell
# 1. Clone / navigate to the project
cd agents\simple

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1     # if blocked: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# 3. Install dependencies
pip install -r ..\..\requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env with your Azure OpenAI endpoint and deployment name

# 5. Log in to Azure CLI
az login

# 6. Run locally (listens on http://localhost:8080/api/messages)
python simple-chat.py
```

To test locally with Teams, expose port 8080 via [Dev Tunnels](https://learn.microsoft.com/azure/developer/dev-tunnels/overview) or `ngrok`, then update the messaging endpoint in the Azure portal.

---

## Agent 365 Setup & Deployment — Step by Step

> All `a365` steps require the virtual environment to be activated.
> Steps marked **[standalone terminal]** require a real PowerShell window (not VS Code integrated terminal) due to Windows Account Manager (WAM) authentication.

### Step 1 — Install `a365` CLI

```powershell
dotnet tool install --global Microsoft.Agents.A365.DevTools.Cli
```

### Step 2 — Verify prerequisites

```powershell
a365 setup requirements
```

All checks must pass before continuing.

### Step 3 — Create Agent Blueprint **[standalone terminal]**

```powershell
cd agents\simple
a365 setup blueprint
```

- Creates an Entra ID application for the agent.
- Registers the messaging endpoint (`https://<webapp>.azurewebsites.net/api/messages`).
- Stamps `BOT_APP_ID`, `CONNECTIONS__*`, and other settings into `.env` automatically.
- Stores the encrypted client secret in `a365.generated.config.json`.

> **Region note**: If your `a365.config.json` uses `koreacentral`, change `location` to `eastus` — Agent 365 endpoint registration only supports US regions during preview.

### Step 4 — Configure MCP permissions **[standalone terminal]**

```powershell
a365 setup permissions mcp
```

### Step 5 — Configure Bot API permissions **[standalone terminal]**

```powershell
a365 setup permissions bot
```

### Step 6 — Create Azure infrastructure

```powershell
a365 setup infrastructure
```

Creates the Azure Resource Group, App Service Plan, and Web App with a system-assigned managed identity.

### Step 7 — Deploy the agent

```powershell
a365 deploy app
```

- Packages `simple-chat.py` and sets the startup command.
- Converts `.env` to Azure App Settings (`.env` file is excluded from the package).
- Uploads to Azure App Service via Kudu zip deploy.
- Azure Oryx installs Python dependencies from `requirements.txt` on the server.

> **Tip**: `requirements.txt` must be present in `agents/simple/` for Oryx to pick it up. If missing, copy it from the repo root.

### Step 8 — Publish to Microsoft Teams **[standalone terminal]**

```powershell
a365 publish
```

Submits the agent to your tenant's M365 Admin Center for deployment to Teams.

---

## Key Files

| File | Purpose |
|---|---|
| `simple-chat.py` | Main application — web server, agent logic, Defender AI, observability |
| `a365.config.json` | Static Agent 365 configuration (committed to source control) |
| `a365.generated.config.json` | Dynamic state with encrypted secrets — **do not commit** |
| `.env` | Runtime environment variables — **do not commit** |
| `.env.example` | Template for `.env` |
| `../../requirements.txt` | Python dependencies for the whole project |

---

## Security Notes

- **Prompt Shields**: Every user message is scanned by `Azure AI Content Safety` before reaching the LLM. Detected attacks are logged with a `[DEFENDER_AI]` prefix and the turn is blocked.
- **Credentials**: `DefaultAzureCredential` is used for all Azure service calls — `az login` locally, Managed Identity on App Service. No secrets in code.
- **`.env` excluded from deploy**: `a365 deploy` automatically excludes `.env` and converts its contents to Azure App Settings.
- **`a365.generated.config.json`**: Contains an encrypted client secret. Add to `.gitignore` and keep secure.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `WAM auth dialog doesn't appear` | Run `a365` from a standalone PowerShell window, not VS Code terminal |
| `InternalServerError` on endpoint registration | Change `location` in `a365.config.json` from `koreacentral` to `eastus` |
| `uv` not found during deploy | Install: `winget install astral-sh.uv` |
| `uv` blocked by App Control Policy | Disable Smart App Control in Windows Security settings, then restart |
| `requirements.txt not found` during Oryx build | Copy `requirements.txt` to `agents/simple/` |
| Agent starts but can't call OpenAI | Assign `Cognitive Services OpenAI User` role to the App Service managed identity |
| `ExecutionPolicy` error activating venv | Run: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
