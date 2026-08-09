from pathlib import Path
from typing import Any

from core.http_client import send_request
from core.models import Account


AUTH_ENDPOINTS_FILE = Path("wordlists") / "auth_endpoints"

DEFAULT_AUTH_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "authenticate",
    "authentication",
    "token",
    "session",
}

EXACT_LOGIN_SEGMENTS = {
    "login",
    "signin",
    "sign-in",
    "authenticate",
}

TOKEN_FIELDS = (
    "access_token",
    "auth_token",
    "token",
    "jwt",
    "id_token",
)

ROLE_FIELDS = (
    "role",
    "roles",
    "user_role",
    "is_admin",
    "is_staff",
    "is_superuser",
    "permissions",
    "scope",
    "authorities",
    "account_type",
    "user_type",
    "privilege",
    "group",
)

def authenticate(
    base_url,
    api_inventory,
    tokenA=None,
    tokenB=None,
    tokenAD=None,
    emailA=None,
    emailB=None,
    emailAD=None,
    usernameA=None,
    usernameB=None,
    usernameAD=None,
    passwordA=None,
    passwordB=None,
    passwordAD=None,
):
    print("[!] Authentication started")

    # Mode 1 : tokens directement fournis
    if tokenA and (tokenB or tokenAD):
        print("[!] Authentication mode: provided tokens")

        return mode_token(
            tokenA=tokenA,
            tokenB=tokenB,
            tokenAD=tokenAD,
        )

    # Construction des identifiants du compte principal
    credentialA = build_credential(
        username=usernameA,
        email=emailA,
        password=passwordA,
        label="A",
    )

    # Compte du même niveau pour les tests BOLA
    credentialB = build_credential(
        username=usernameB,
        email=emailB,
        password=passwordB,
        label="B",
    )

    # Compte privilégié pour les tests BFLA
    credentialAD = build_credential(
        username=usernameAD,
        email=emailAD,
        password=passwordAD,
        label="AD",
    )

    # Le compte A est obligatoire.
    # Au moins B ou AD doit être fourni.
    if credentialA and (credentialB or credentialAD):
        print("[!] Authentication mode: credentials")

        return mode_credentials(
            base_url=base_url,
            api_inventory=api_inventory,
            credentialA=credentialA,
            credentialB=credentialB,
            credentialAD=credentialAD,
        )

    raise ValueError(
        "Authentication requires:\n"
        "- account A using tokenA or complete credentials,\n"
        "- and at least account B or account AD.\n\n"
        "Valid token examples:\n"
        "- tokenA and tokenB for BOLA,\n"
        "- tokenA and tokenAD for BFLA,\n"
        "- tokenA, tokenB and tokenAD for both.\n\n"
        "The same combinations are supported with credentials."
    )

def mode_token(tokenA, tokenB=None, tokenAD=None):

    accountA = Account(
        Label="A",
        token=tokenA,
    )

    accountB = None
    accountAD = None

    if tokenB:
        accountB = Account(
            Label="B",
            token=tokenB,
        )

    if tokenAD:
        accountAD = Account(
            Label="AD",
            token=tokenAD,
        )

    print("[+] Account A initialized with provided token")

    if accountB:
        print("[+] Account B initialized with provided token")

    if accountAD:
        print("[+] Account AD initialized with provided token")

    return accountA, accountB, accountAD

def mode_credentials(
    base_url,
    api_inventory,
    credentialA,
    credentialB=None,
    credentialAD=None,
):
    login_endpoint = find_login_endpoint(api_inventory)
    login_url = build_url(base_url, login_endpoint.path)

    print(
        f"[+] Selected login endpoint: "
        f"{login_endpoint.method} {login_endpoint.path}"
    )

    # Authentification du compte principal
    tokenA,roleA = authenticate_account(
        login_url=login_url,
        credential=credentialA,
    )

    accountA = create_account_from_credential(
        label="A",
        credential=credentialA,
        token=tokenA,
        role=roleA
    )

    accountB = None
    accountAD = None

    # Authentification du compte B seulement s'il est fourni
    if credentialB:
        tokenB,roleB = authenticate_account(
            login_url=login_url,
            credential=credentialB,
        )

        accountB = create_account_from_credential(
            label="B",
            credential=credentialB,
            token=tokenB,
            role=roleB
        )

    # Authentification du compte admin seulement s'il est fourni
    if credentialAD:
        tokenAD,roleAD = authenticate_account(
            login_url=login_url,
            credential=credentialAD,
        )

        accountAD = create_account_from_credential(
            label="AD",
            credential=credentialAD,
            token=tokenAD,
            role=roleAD
        )

    print("[+] Account A authenticated successfully")

    if accountB:
        print("[+] Account B authenticated successfully")

    if accountAD:
        print("[+] Account AD authenticated successfully")

    return accountA, accountB, accountAD

def build_credential(username=None, email=None, password=None, label=None):

    if not password:
        return None

    if username:
        return {
            "label": label,
            "identifier_field": "username",
            "identifier_value": username,
            "password": password,
        }

    if email:
        return {
            "label": label,
            "identifier_field": "email",
            "identifier_value": email,
            "password": password,
        }

    return None


def find_login_endpoint(api_inventory):
    auth_keywords = load_auth_keywords()
    candidates = []

    for endpoint in api_inventory:
        if endpoint.method.upper() != "POST":
            continue

        score = score_login_endpoint(endpoint, auth_keywords)

        if score > 0:
            candidates.append((score, endpoint))

    if not candidates:
        raise RuntimeError(
            "No potential authentication endpoint was found "
            "in the API inventory."
        )

    candidates.sort(key=lambda item: item[0], reverse=True)

    best_score, best_endpoint = candidates[0]

    print("[!] Potential authentication endpoints:")

    for score, endpoint in candidates:
        print(f"    score={score:<2} {endpoint.method} {endpoint.path}")

    if len(candidates) > 1:
        second_score = candidates[1][0]

        if second_score == best_score:
            tied_paths = [
                endpoint.path
                for score, endpoint in candidates
                if score == best_score
            ]

            raise RuntimeError(
                "Multiple authentication endpoints have the same score: "
                + ", ".join(tied_paths)
            )

    return best_endpoint


def score_login_endpoint(endpoint, auth_keywords):
    score = 0
    path = endpoint.path.lower()
    segments = {
        segment
        for segment in path.strip("/").split("/")
        if segment
    }

    if segments.intersection(EXACT_LOGIN_SEGMENTS):
        score += 10

    for keyword in auth_keywords:
        if keyword in path:
            score += 3

    operation_id = (endpoint.operation_id or "").lower()
    summary = (endpoint.summary or "").lower()
    description = (endpoint.description or "").lower()

    tags = endpoint.tags or []
    normalized_tags = " ".join(str(tag).lower() for tag in tags)

    searchable_text = " ".join(
        [
            operation_id,
            summary,
            description,
            normalized_tags,
        ]
    )

    for keyword in auth_keywords:
        if keyword in searchable_text:
            score += 1

    return score


def load_auth_keywords():
    keywords = set(DEFAULT_AUTH_KEYWORDS)

    if not AUTH_ENDPOINTS_FILE.exists():
        return keywords

    try:
        with AUTH_ENDPOINTS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                keyword = line.strip().lower()

                if keyword and not keyword.startswith("#"):
                    keywords.add(keyword)

    except OSError as exc:
        print(
            f"[!] Unable to read {AUTH_ENDPOINTS_FILE}: {exc}. "
            "Default authentication keywords will be used."
        )

    return keywords


def authenticate_account(login_url, credential):

    label = credential["label"]

    request_body = {
        credential["identifier_field"]: credential["identifier_value"],
        "password": credential["password"],
    }

    response = send_request(
        method="POST",
        url=login_url,
        json_body=request_body,
    )

    if response is None:
        raise ConnectionError(
            f"Authentication request failed for account {label}."
        )

    if not response.ok:
        raise RuntimeError(
            f"Authentication failed for account {label}: "
            f"HTTP {response.status_code}."
        )

    try:
        response_data = response.json()

    except ValueError as exc:
        raise ValueError(
            f"Authentication response for account {label} "
            "is not valid JSON."
        ) from exc

    token = extract_token(response_data)
    role=extract_role(response_data)

    if not token:
        raise ValueError(
            f"No authentication token was found for account {label}."
        )

    return token,role


def extract_token(response_data):
    if not isinstance(response_data, dict):
        return None

    for field in TOKEN_FIELDS:
        value = response_data.get(field)

        if isinstance(value, str) and value.strip():
            return value

    for value in response_data.values():
        if isinstance(value, dict):
            token = extract_token(value)

            if token:
                return token

    return None

# we need to extract the role even if it is nested in the response.json() and even if the field value is boolean, value or a list 
def extract_role(response_data):
    # response.json() is usually a dictionnary, let's make sure of that using isinstance(value,type)
    if not isinstance(response_data, dict):
        return None

    for field in ROLE_FIELDS:
        
        if field not in response_data:
            continue

        value = response_data[field]

        if isinstance(value, str) and value.strip():
            return value

        if isinstance(value, bool):
            return {
                "field": field,
                "value": value,
            }

        if isinstance(value, list) and value:
            return value

    for value in response_data.values():
        if isinstance(value, dict):
            role = extract_role(value)

            if role is not None:
                return role

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    role = extract_role(item)

                    if role is not None:
                        return role

    return None

def create_account_from_credential(label, credential, token,role):
    account_data: dict[str, Any] = {
        "Label": label,
        "password": credential["password"],
        "token": token,
        "role": role
    }

    identifier_field = credential["identifier_field"]
    identifier_value = credential["identifier_value"]

    if identifier_field == "username":
        account_data["username"] = identifier_value

    elif identifier_field == "email":
        account_data["email"] = identifier_value

    return Account(**account_data)


def build_url(base_url, path):
    if not base_url:
        raise ValueError("The base URL cannot be empty.")

    if not path:
        raise ValueError("The endpoint path cannot be empty.")

    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"