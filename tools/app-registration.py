# python app to register an application with deleted permissions 
# 1. Propmt the user for application name
# 2. Registers an app to Microsoft Entra
# 3. Assign DELEGATED PERMISSION to the APP (NOT Application)
#  - Application.ReadWrite.All
#  - AgentIdentityBlueprint.ReadWrite.All
#  - AgentIdentityBlueprint.UpdateAuthProperties.All
#  - DelegatedPermissionGrant.ReadWrite.All
#  - Directory.Read.All
# 4. Saves the result data such as Application ID into application.json


import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import msal
import requests


GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"
DEFAULT_PUBLIC_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


def _graph_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    expected: Tuple[int, ...] = (200,),
    timeout_seconds: int = 60,
    max_retries: int = 4,
) -> requests.Response:
    for attempt in range(max_retries):
        resp = session.request(
            method,
            url,
            params=params,
            json=json_body,
            timeout=timeout_seconds,
        )

        if resp.status_code in expected:
            return resp

        if resp.status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
            retry_after = resp.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    sleep_seconds = int(retry_after)
                except ValueError:
                    sleep_seconds = 2**attempt
            else:
                sleep_seconds = 2**attempt
            time.sleep(sleep_seconds)
            continue

        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise RuntimeError(
            f"Graph request failed: {method} {url} -> {resp.status_code}. Details: {detail}"
        )

    raise RuntimeError(f"Graph request failed after retries: {method} {url}")


def _acquire_token_device_code(tenant_id: str, scopes: List[str], client_id: str) -> str:
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.PublicClientApplication(client_id=client_id, authority=authority)
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        raise RuntimeError(f"Failed to create device flow. Details: {flow}")
    print(flow["message"], file=sys.stderr)
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Failed to acquire token. Details: {result}")
    return result["access_token"]


def _find_az_executable(explicit_path: Optional[str]) -> List[str]:
    if explicit_path:
        return [explicit_path]

    resolved = shutil.which("az")
    if resolved:
        return [resolved]

    # Common Windows install locations
    local_app_data = os.environ.get("LOCALAPPDATA")
    program_files = os.environ.get("ProgramFiles")
    candidates: List[str] = []
    if local_app_data:
        candidates.append(os.path.join(local_app_data, "Programs", "Microsoft SDKs", "Azure", "CLI2", "wbin", "az.cmd"))
        candidates.append(os.path.join(local_app_data, "Programs", "Microsoft SDKs", "Azure", "CLI2", "wbin", "az.exe"))
    if program_files:
        candidates.append(os.path.join(program_files, "Microsoft SDKs", "Azure", "CLI2", "wbin", "az.cmd"))
        candidates.append(os.path.join(program_files, "Microsoft SDKs", "Azure", "CLI2", "wbin", "az.exe"))

    for c in candidates:
        if os.path.exists(c):
            return [c]

    return ["az"]


def _acquire_token_az_cli(tenant_id: str, az_path: Optional[str]) -> str:
    az_cmd = _find_az_executable(az_path)
    try:
        completed = subprocess.run(
            az_cmd
            + [
                "account",
                "get-access-token",
                "--resource-type",
                "ms-graph",
                "--tenant",
                tenant_id,
                "--output",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "Azure CLI (az) was not found. Install Azure CLI or pass --az-path, or use --auth devicecode."
        ) from e
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or "").strip()
        raise RuntimeError(
            "Failed to acquire token from Azure CLI. Run: az login --tenant <tenant>. "
            f"Details: {msg}"
        ) from e

    data = json.loads(completed.stdout)
    token = data.get("accessToken")
    if not token:
        raise RuntimeError(f"Azure CLI token response did not include accessToken: {data}")
    return token


def _prompt_app_name(explicit_name: Optional[str]) -> str:
    if explicit_name and explicit_name.strip():
        return explicit_name.strip()
    name = input("Application name: ").strip()
    if not name:
        raise ValueError("Application name is required")
    return name


def _find_application_by_display_name(session: requests.Session, display_name: str) -> Optional[Dict[str, Any]]:
    escaped = display_name.replace("'", "''")
    resp = _graph_request(
        session,
        "GET",
        f"{GRAPH_BASE_URL}/applications",
        params={"$filter": f"displayName eq '{escaped}'", "$top": 1},
        expected=(200,),
    )
    data = resp.json()
    values = data.get("value") or []
    return values[0] if values else None


def _create_application(session: requests.Session, display_name: str) -> Dict[str, Any]:
    resp = _graph_request(
        session,
        "POST",
        f"{GRAPH_BASE_URL}/applications",
        json_body={"displayName": display_name, "signInAudience": "AzureADMyOrg"},
        expected=(201,),
    )
    return resp.json()


def _ensure_service_principal(session: requests.Session, app_id: str) -> Dict[str, Any]:
    resp = _graph_request(
        session,
        "GET",
        f"{GRAPH_BASE_URL}/servicePrincipals",
        params={"$filter": f"appId eq '{app_id}'", "$top": 1},
        expected=(200,),
    )
    values = (resp.json().get("value") or [])
    if values:
        return values[0]

    resp = _graph_request(
        session,
        "POST",
        f"{GRAPH_BASE_URL}/servicePrincipals",
        json_body={"appId": app_id},
        expected=(201,),
    )
    return resp.json()


def _get_graph_service_principal(session: requests.Session) -> Dict[str, Any]:
    resp = _graph_request(
        session,
        "GET",
        f"{GRAPH_BASE_URL}/servicePrincipals",
        params={
            "$filter": f"appId eq '{GRAPH_RESOURCE_APP_ID}'",
            "$select": "id,appId,displayName,oauth2PermissionScopes",
            "$top": 1,
        },
        expected=(200,),
    )
    values = resp.json().get("value") or []
    if not values:
        raise RuntimeError("Microsoft Graph service principal not found in tenant")
    return values[0]


def _resolve_scope_ids(graph_sp: Dict[str, Any], scope_values: Iterable[str]) -> Dict[str, str]:
    scopes = graph_sp.get("oauth2PermissionScopes") or []
    by_value: Dict[str, str] = {}
    for s in scopes:
        val = s.get("value")
        sid = s.get("id")
        if val and sid:
            by_value[val] = sid

    missing: List[str] = []
    resolved: Dict[str, str] = {}
    for v in scope_values:
        sid = by_value.get(v)
        if not sid:
            missing.append(v)
        else:
            resolved[v] = sid

    if missing:
        raise RuntimeError(
            "Unable to resolve delegated permission scope IDs for: "
            + ", ".join(missing)
            + ". Ensure these delegated scopes exist in Microsoft Graph for this tenant."
        )
    return resolved


def _set_delegated_permissions(
    session: requests.Session,
    application_object_id: str,
    delegated_scope_ids: Dict[str, str],
) -> None:
    required_resource_access = [
        {
            "resourceAppId": GRAPH_RESOURCE_APP_ID,
            "resourceAccess": [
                {"id": sid, "type": "Scope"} for _, sid in sorted(delegated_scope_ids.items())
            ],
        }
    ]

    _graph_request(
        session,
        "PATCH",
        f"{GRAPH_BASE_URL}/applications/{application_object_id}",
        json_body={"requiredResourceAccess": required_resource_access},
        expected=(204,),
    )


def _grant_admin_consent(
    session: requests.Session,
    client_service_principal_id: str,
    resource_service_principal_id: str,
    scope_values: List[str],
) -> Dict[str, Any]:
    scope_str = " ".join(scope_values)
    resp = _graph_request(
        session,
        "POST",
        f"{GRAPH_BASE_URL}/oauth2PermissionGrants",
        json_body={
            "clientId": client_service_principal_id,
            "consentType": "AllPrincipals",
            "resourceId": resource_service_principal_id,
            "scope": scope_str,
        },
        expected=(201,),
    )
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID") or "organizations")
    parser.add_argument("--app-name", default=None)
    parser.add_argument("--output", default="application.json")
    parser.add_argument("--admin-consent", action="store_true", default=False)
    parser.add_argument(
        "--auth",
        choices=["azcli", "devicecode", "token"],
        default=os.environ.get("AZURE_AUTH_METHOD") or "azcli",
    )
    parser.add_argument(
        "--device-client-id",
        default=os.environ.get("AZURE_DEVICE_CLIENT_ID") or DEFAULT_PUBLIC_CLIENT_ID,
    )
    parser.add_argument(
        "--access-token",
        default=os.environ.get("AZURE_ACCESS_TOKEN"),
    )
    parser.add_argument(
        "--az-path",
        default=os.environ.get("AZURE_CLI_PATH"),
    )
    args = parser.parse_args()

    delegated_permissions = [
        "Application.ReadWrite.All",
        "AgentIdentityBlueprint.ReadWrite.All",
        "AgentIdentityBlueprint.UpdateAuthProperties.All",
        "DelegatedPermissionGrant.ReadWrite.All",
        "Directory.Read.All",
    ]

    if args.auth == "token":
        if not args.access_token:
            raise RuntimeError(
                "--auth token requires --access-token (or env var AZURE_ACCESS_TOKEN)"
            )
        token = args.access_token
    elif args.auth == "azcli":
        try:
            token = _acquire_token_az_cli(args.tenant_id, az_path=args.az_path)
        except RuntimeError as e:
            if "Azure CLI (az) was not found" in str(e):
                raise RuntimeError(
                    "Azure CLI (az) was not found on PATH. Either install Azure CLI, or run with "
                    "--auth devicecode --device-client-id <YOUR_CLIENT_ID>, or use --auth token --access-token <TOKEN>."
                ) from e
            raise
    else:
        scopes = [f"https://graph.microsoft.com/{p}" for p in delegated_permissions]
        token = _acquire_token_device_code(
            args.tenant_id,
            scopes=scopes,
            client_id=args.device_client_id,
        )

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    )

    display_name = _prompt_app_name(args.app_name)
    existing = _find_application_by_display_name(session, display_name)
    if existing:
        application = existing
    else:
        application = _create_application(session, display_name)

    app_object_id = application["id"]
    app_id = application["appId"]

    app_sp = _ensure_service_principal(session, app_id)
    graph_sp = _get_graph_service_principal(session)
    scope_ids = _resolve_scope_ids(graph_sp, delegated_permissions)

    _set_delegated_permissions(session, app_object_id, scope_ids)

    grant: Optional[Dict[str, Any]] = None
    if args.admin_consent:
        grant = _grant_admin_consent(
            session,
            client_service_principal_id=app_sp["id"],
            resource_service_principal_id=graph_sp["id"],
            scope_values=delegated_permissions,
        )

    result = {
        "tenantId": args.tenant_id,
        "displayName": display_name,
        "applicationObjectId": app_object_id,
        "applicationId": app_id,
        "servicePrincipalId": app_sp.get("id"),
        "requiredDelegatedPermissions": delegated_permissions,
        "requiredDelegatedPermissionScopeIds": scope_ids,
        "adminConsentGrant": grant,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
