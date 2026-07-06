import msal
import requests

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPES = [
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/UserAuthenticationMethod.Read.All",
]


def get_access_token(client_id, tenant_id):
    app = msal.PublicClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}"
    )

    flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
    print(f"\n{flow['message']}\n")

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        raise RuntimeError(result.get("error_description", "Failed to acquire access token"))

    return result["access_token"]


def has_mfa_registered(user_id, headers):
    url = f"{GRAPH_BASE_URL}/users/{user_id}/authentication/methods"
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    methods = response.json().get("value", [])

    for method in methods:
        method_type = method.get("@odata.type", "")
        if "passwordAuthenticationMethod" not in method_type:
            return True

    return False


def fetch_live_users(client_id, tenant_id):
    token = get_access_token(client_id, tenant_id)
    headers = {"Authorization": f"Bearer {token}"}

    users = []
    url = (
        f"{GRAPH_BASE_URL}/users"
        "?$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses"
    )

    while url:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        for user in data.get("value", []):
            users.append({
                "display_name": user.get("displayName"),
                "user_principal_name": user.get("userPrincipalName"),
                "account_enabled": user.get("accountEnabled"),
                "user_type": user.get("userType"),
                "licensed": bool(user.get("assignedLicenses")),
                "mfa_registered": has_mfa_registered(user["id"], headers),
            })

        url = data.get("@odata.nextLink")

    return users
