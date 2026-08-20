# This is the main BOLA script that we gonna implement to code BOLA vulnerability.
# BOLA is when user A can access user B resources.

from core.http_client import send_request
from pathlib import Path
import json
from display import (
    display_bola_header, display_candidate, display_id_found,
    display_result, display_bodies,
)
from core.models import Finding


BOLA_Object_Identifier_wordlist = Path("wordlists") / "BOLA_Object_Identifier"
HAR_A = Path("HarFiles") / "HarA.har"
HAR_B = Path("HarFiles") / "HarB.har"


BOLA_TOP = {
    "id",
    "user",
    "username",
    "me",
    "self",
    "owner",
    "account",
    "profile",
    "order",
    "customer",
    "document"
}
login = {
    'token',
    'register',
    'login',
    
}

# BOLA ENGINE VERSION: 2

def bola(endpoints, accounts, url,safe_bola):
    print(safe_bola)

    accountA = accounts[0]
    accountB = accounts[1]

    intial_bola_endpoints = []
    findings = []

    display_bola_header()
    print("[!] Potential BOLA vulnerable paths:")

    # ---------------------------------------------------------
    # Find potential BOLA endpoints
    #
    # OLD:
    # only GET + object candidate
    #
    # NOW:
    # object in path OR required request body
    # ---------------------------------------------------------

    for endpoint in endpoints:
        if endpoint is None and not endpoint.authentication.required:
            continue
        is_login=False
        for auth in login:
            if auth in endpoint.path:
                print("auth endpoint identified, ignored")
                is_login=True
        if is_login:
            continue
        if safe_bola:
            if endpoint.method != 'GET':
                continue
        body_is_required = getattr(endpoint.request_body, "required", False)
        object_is_required = endpoint.object_candidates

        if object_is_required or body_is_required:
            print(f"\t{endpoint.method}       {endpoint.path}")
            intial_bola_endpoints.append(endpoint)

    bola_endpoints = find_bola_endpoints(intial_bola_endpoints)
    bola_endpoints.sort(key=lambda item: item[0], reverse=True)

    # ---------------------------------------------------------
    # Test each candidate
    # ---------------------------------------------------------

    for score, bola_endpoint in bola_endpoints:
        print("--------------------------------------------------------\n\n")

        method = bola_endpoint.method
        request_url = url.rstrip("/") + "/" + bola_endpoint.path.lstrip("/")
        display_candidate(score, method, bola_endpoint.path)
        headersA = {
            "Authorization": f"Bearer {accountA.token}",
            "Content-Type": "application/json",
        }
        headersB = {
            "Authorization": f"Bearer {accountB.token}",
            "Content-Type": "application/json",
        }
        found_values_A = {
            "request_body": {},
            "object_id": {}
        }
        found_values_B = {
            "request_body": {},
            "object_id": {}
        }
        # ---------------------------------------------------------
        # CASE 1:
        # object identifier is inside the path
        #
        # Example:
        # GET /documents/{documentId}
        # DELETE /documents/{documentId}
        # ---------------------------------------------------------
        segments = request_url.split("/")
        index = find_objID(segments)
        # Default URLs when there is no object in the path.
        userAendpoint = request_url
        userBendpoint = request_url
        if index is not None:
            print(f"Index: {index}")
            userAendpoint = substitute_objID(
                accountA,
                segments[:],
                index,
                bola_path=request_url,
                Har_file=HAR_A
            )

            userBendpoint = substitute_objID(
                accountB,
                segments[:],
                index,
                bola_path=request_url,
                Har_file=HAR_B
            )

            if userAendpoint is None or userBendpoint is None:
                print("[-] Unable to build both users urls!")
                continue

            print(f"\tuserA endpoint: {userAendpoint}")
            print(f"\tuserB endpoint: {userBendpoint}")

        # ---------------------------------------------------------
        # CASE 2:
        # endpoint uses a request body
        #
        # Example:
        #
        # PUT /documents
        # {
        #     "documentId": 15,
        #     "title": "hello"
        # }
        #
        # Logic reused from bfla.py
        # ---------------------------------------------------------

        body_is_required = getattr(bola_endpoint.request_body, "required", False)

        if body_is_required:
            PROPS = (bola_endpoint.request_body and bola_endpoint.request_body.properties) or {}
            ATTRIBUTE = [property for property in PROPS if property]

            print(f"[!] Request body attributes: {ATTRIBUTE}")

            valid_GET_endpoints = find_valid_GET_endpoints(ATTRIBUTE, endpoints)

            if not valid_GET_endpoints:
                target = None
            else:
                target = valid_GET_endpoints[0]

            if target:
                print(f"[!] Possible producer GET endpoint: {target.path}")

                # -------------------------------------------------
                # Build producer GET endpoint for user A
                # -------------------------------------------------

                if not findobj(target):
                    get_url_A = url.rstrip("/") + "/" + target.path.lstrip("/")

                else:
                    id_A = retrieve_id(HAR_A, target.path) or ""

                    index_A, _ = findobj(target)[0]
                    seg_tar_A = target.path.strip("/").split("/")
                    seg_tar_A[index_A] = str(id_A)

                    target_url_A = "/".join(seg_tar_A)
                    get_url_A = url.rstrip("/") + "/" + target_url_A.lstrip("/")

                # -------------------------------------------------
                # Build producer GET endpoint for user B
                # -------------------------------------------------

                if not findobj(target):
                    get_url_B = url.rstrip("/") + "/" + target.path.lstrip("/")

                else:
                    id_B = retrieve_id(HAR_B, target.path) or ""

                    index_B, _ = findobj(target)[0]
                    seg_tar_B = target.path.strip("/").split("/")
                    seg_tar_B[index_B] = str(id_B)

                    target_url_B = "/".join(seg_tar_B)
                    get_url_B = url.rstrip("/") + "/" + target_url_B.lstrip("/")

                # -------------------------------------------------
                # Retrieve A and B values
                # -------------------------------------------------

                response_A = send_request("GET", get_url_A, headersA)
                response_B = send_request("GET", get_url_B, headersB)

                body_A = safe_json(response_A)
                body_B = safe_json(response_B)

                for attribute in ATTRIBUTE:

                    if response_A is not None and 200 <= response_A.status_code < 300:
                        found_values_A["request_body"][attribute] = extract_field(body_A, [attribute])
                    else:
                        found_values_A["request_body"][attribute] = None

                    if response_B is not None and 200 <= response_B.status_code < 300:
                        found_values_B["request_body"][attribute] = extract_field(body_B, [attribute])
                    else:
                        found_values_B["request_body"][attribute] = None

                print(f"[!] User A body values: {found_values_A['request_body']}")
                print(f"[!] User B body values: {found_values_B['request_body']}")

            else:
                print("[-] No GET endpoint found to retrieve request body values")

        # ---------------------------------------------------------
        # BASELINE
        #
        # A token + A object
        # B token + B object
        # ---------------------------------------------------------

        try:
            baseA = make_normal_request(
                account=accountA,
                url=userAendpoint,
                method=method,
                body=found_values_A["request_body"]
            )

            baseB = make_normal_request(
                account=accountB,
                url=userBendpoint,
                method=method,
                body=found_values_B["request_body"]
            )

            print(f"\tresponse A: {baseA}")
            print(f"\tresponse B: {baseB}")

        except Exception as e:
            print(f"error: [{e}]")
            continue

        if baseA is None or baseB is None:
            print("[!] One of the baseline requests failed")
            continue

        # ---------------------------------------------------------
        # HTTP SUCCESS VALIDATION
        #
        # Instead of:
        # status_code == 200
        #
        # Accept:
        # 200 <= status < 300
        #
        # Examples:
        # 200 OK
        # 201 Created
        # 202 Accepted
        # 204 No Content
        # ---------------------------------------------------------

        if not is_successful_response(baseA):
            print(f"[-] User A baseline failed: HTTP {baseA.status_code}")
            continue

        if not is_successful_response(baseB):
            print(f"[-] User B baseline failed: HTTP {baseB.status_code}")
            continue

        print("normal requests were successful")
        print("initializing cross requests")

        # ---------------------------------------------------------
        # CROSS A
        #
        # Alice token
        # Bob URL
        # Bob body
        # ---------------------------------------------------------

        crossA = make_bola_request(
            accountA,
            accountB,
            userBendpoint,
            method=method,
            body=found_values_B["request_body"]
        )

        # ---------------------------------------------------------
        # CROSS B
        #
        # Bob token
        # Alice URL
        # Alice body
        # ---------------------------------------------------------

        crossB = make_bola_request(
            accountB,
            accountA,
            userAendpoint,
            method=method,
            body=found_values_A["request_body"]
        )

        if crossA is None or crossB is None:
            print("[!] One of the cross requests failed")
            continue

        # ---------------------------------------------------------
        # BOLA RESPONSE VALIDATION
        # ---------------------------------------------------------

        if is_successful_response(crossA):

            # Strongest current evidence:
            # Alice received exactly Bob's legitimate response.
            if crossA.text == baseB.text:
                confidence = "CONFIRMED"

            # HTTP request succeeded but response differs.
            #
            # This is especially possible with PUT / PATCH /
            # POST / DELETE where the server may simply return:
            #
            # {"message": "updated"}
            #
            # or 204 No Content.
            else:
                confidence = "HIGH"

            display_result(
                True,
                bola_endpoint.path,
                accountA.Label,
                accountB.Label
            )

            display_bodies(
                crossA.text,
                baseB.text,
                accountA.Label,
                accountB.Label
            )

            finding = Finding(
                vulnerability="BOLA",
                endpoint=bola_endpoint,
                confidence=confidence,
                evidence={
                    "account": accountA,
                    "status_code": crossA.status_code,
                    "base_response_body": baseB.text,
                    "cross_response_body": crossA.text,
                    "method": method,
                    "request_body": found_values_B["request_body"]
                }
            )

            findings.append(finding)

        else:
            print(f"[-] Cross request rejected: HTTP {crossA.status_code}")

            display_result(
                False,
                bola_endpoint.path,
                accountA.Label,
                accountB.Label
            )

    return findings


# =============================================================
# HTTP SUCCESS CHECK
# =============================================================

def is_successful_response(response):
    if response is None:
        return False

    return 200 <= response.status_code < 300


# =============================================================
# FIND BOLA CANDIDATES
# =============================================================

def find_bola_endpoints(initial_bola_endpoints):
    print("[!] Identifying BOLA endpoints url:")

    wordlist = loadwordlist()
    bola_endpoints = []

    for endpoint in initial_bola_endpoints:
        score = 0

        # ---------------------------------------------------------
        # Path object identifiers
        # ---------------------------------------------------------

        sp_obj_id = endpoint.path.split("/")

        for obj in sp_obj_id:
            if obj.startswith("{") and obj.endswith("}"):
                obj = obj.strip("{}")
                obj_lower = obj.lower()

                if obj_lower in BOLA_TOP:
                    score += 10

                elif obj_lower.endswith("id"):
                    score += 8

                elif obj_lower in wordlist:
                    score += 5

        # ---------------------------------------------------------
        # Request body object identifiers
        #
        # Same BOLA indicators, just applied to body properties.
        # ---------------------------------------------------------

        properties = (endpoint.request_body and endpoint.request_body.properties) or {}

        for property_name in properties:
            prop = property_name.lower()

            if prop in BOLA_TOP:
                score += 10

            elif prop.endswith("id"):
                score += 8

            elif prop in wordlist:
                score += 5

        body_is_required = getattr(endpoint.request_body, "required", False)

        if score > 0:
            bola_endpoints.append((score, endpoint))

        elif body_is_required:
            bola_endpoints.append((score, endpoint))

    return bola_endpoints


# =============================================================
# LOAD WORDLIST
# =============================================================

def loadwordlist():
    keywords = set({})
    try:
        with BOLA_Object_Identifier_wordlist.open("r", encoding="utf-8") as file:

            for line in file:
                keyword = line.strip().lower()

                if keyword and not keyword.startswith("#"):
                    keywords.add(keyword)

    except OSError as exc:
        print(
            f"[!] Unable to read {BOLA_Object_Identifier_wordlist}: {exc}. "
            "Default authentication keywords will be used."
        )

    return keywords


# =============================================================
# NORMAL REQUEST
#
# Now accepts any HTTP method + optional JSON body.
# =============================================================

def make_normal_request(account, url, method="GET", body=None):
    print(f"sending request as user {account.Label}")
    headers = {
        "Authorization": f"Bearer {account.token}",
        "Content-Type": "application/json",
    }
    ans = send_request(
        method,
        url=url,
        headers=headers,
        json_body=body
    )
    return ans


# =============================================================
# FIND OBJECT ID INSIDE PATH
# =============================================================

def find_objID(segments):
    for i, seg in enumerate(segments):
        if seg.startswith("{") and seg.endswith("}"):
            return i
    return None


# =============================================================
# SUBSTITUTE OBJECT ID
# =============================================================

def substitute_objID(account, segments, index, bola_path, Har_file):
    object = segments[index].strip("{}")
    if object == "username":
        segments[index] = account.username
    elif object == "email":
        segments[index] = account.email
    elif object.lower().endswith("id"):
        id = retrieve_id(Har_file, bola_path)
        if id is None:
            print(f"[-] Unable to retrieve {object} from the HAR file")
            return None
        segments[index] = id
    return "/".join(segments)


# =============================================================
# RETRIEVE OBJECT ID FROM HAR
# =============================================================

def retrieve_id(Har_file, bola_path):
    segments = bola_path.split("/")
    index = find_objID(segments)
    if index is None:
        return None
    try:
        with open(Har_file, encoding="utf-8") as f:
            har = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Unable to read HAR file {Har_file}: {e}")
        return None
    entries = har.get("log", {}).get("entries", [])
    for entry in entries:
        har_url = entry.get("request", {}).get("url")
        if not har_url:
            continue
        seg_har_url = har_url.split("/")
        if len(seg_har_url) != len(segments):
            continue
        if all(b == h for i, (b, h) in enumerate(zip(segments, seg_har_url)) if i != index):
            id = seg_har_url[index]
            if any(c in id for c in ("&", "?", "=")):
                continue
            print(f"\t[!] Id possibly found in {har_url}")
            print(f"\t[?] Id: {id}")
            return id
    return None


# =============================================================
# CROSS BOLA REQUEST
#
# Now accepts any HTTP method + optional JSON body.
# =============================================================

def make_bola_request(account1, account2, bola_url, method="GET", body=None):
    print(
        f"[!] sending request as user {account1.Label} "
        f"to endpoint {bola_url} belonging to {account2.Label}"
    )
    headers = {
        "Authorization": f"Bearer {account1.token}",
        "Content-Type": "application/json",
    }
    ans = send_request(method,url=bola_url,headers=headers,json_body=body)
    return ans


# =============================================================
# FIND GET ENDPOINTS THAT CAN PRODUCE VALUES
#
# Reused from bfla.py.
# =============================================================

def find_valid_GET_endpoints(attributes, ALL_endpoints, check_path_with_obj=False):
    valid_GET_endpoints = []
    for other_endpoint in ALL_endpoints:
        if other_endpoint.method != "GET":
            continue
        if findobj(other_endpoint.path) and check_path_with_obj is False:
            continue
        check_properties = (
            other_endpoint.responses
            and other_endpoint.responses.properties
        ) or {}
        if "id" in attributes:
            found = False
            for element in attributes:
                if check_properties_presence(check_properties, element):
                    found = True
                    break
        else:
            found = all(
                check_properties_presence(check_properties, element)
                for element in attributes
            )
        if found:
            valid_GET_endpoints.append(other_endpoint)
    # If nothing was found, retry GET endpoints containing {id}.
    if not valid_GET_endpoints and check_path_with_obj is False:
        return find_valid_GET_endpoints(
            attributes,
            ALL_endpoints,
            check_path_with_obj=True
        )
    return valid_GET_endpoints


# =============================================================
# CHECK RESPONSE SCHEMA PROPERTIES
#
# Reused from bfla.py.
# =============================================================

def check_properties_presence(properties, target):
    if not isinstance(properties, dict):
        return False
    for key, value in properties.items():
        if key == target:
            return True
        if isinstance(value, str):
            if value == target:
                return True
        elif isinstance(value, dict):
            if check_properties_presence(value, target):
                return True
    return False

# =============================================================
# RECURSIVELY EXTRACT FIELD FROM JSON
#
# Reused from bfla.py.
# =============================================================

def extract_field(response_data, target_fields, exclude=None):
    if not isinstance(response_data, dict):
        if ( isinstance(response_data, list) and response_data and isinstance(response_data[0], dict)):
            response_data = response_data[0]
        else:
            return None
    for field in target_fields:
        if field not in response_data:
            continue
        value = response_data[field]
        if isinstance(value, str) and value.strip():
            if exclude is not None and value in exclude:
                continue
            return value
        if isinstance(value, bool):
            return {
                "field": field,
                "value": value,
            }
        if isinstance(value, (int, float)):
            if exclude is not None and value in exclude:
                continue
            return value
        if isinstance(value, list) and value:
            return value
    for value in response_data.values():
        if isinstance(value, dict):
            result = extract_field( value, target_fields,exclude )
            if result is not None:
                return result
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    result = extract_field(item,target_fields, exclude )
                    if result is not None:
                        return result
    return None


# =============================================================
# SAFE JSON
# =============================================================

def safe_json(response):
    if response is None:
        return {}
    try:
        return response.json()
    except ValueError:
        return {}


# =============================================================
# FIND {OBJECT} IN PATH
#
# Reused from bfla.py.
# =============================================================

def findobj(endpoint):
    if isinstance(endpoint, str):
        path = endpoint
    else:
        path = endpoint.path

    segments = path.strip("/").split("/")
    objects = []

    for i, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            object_id = segment.strip("{}")
            objects.append((i, object_id))
    return objects


# =============================================================
# DEBUG HELPER
# =============================================================

def show_bodies(body_a, body_b):
    def fmt(b):
        try:
            return json.dumps(json.loads(b), indent=2)
        except ValueError:
            return b

    print("-" * 60)
    print("USER A:\n" + fmt(body_a))
    print("-" * 60)
    print("USER B:\n" + fmt(body_b))
    print("-" * 60)