# Version: 2
# script objective: be able to enumerate an API with only an url provided and transform it into a commun endpoint object
from core.http_client import send_request
from core.graphql_client import send_graphql_request
from core.models import Authentication, GraphQLField, GraphQLArgument, GraphQLOperation, GraphQLSchema, Endpoint, Parameter, RequestBody, Response
from auth.ses import authenticate
from graphql import (
    build_client_schema,
    get_named_type,
    is_non_null_type,
    is_scalar_type,
    is_enum_type,
    is_object_type,
    is_interface_type,
    is_union_type,
    Undefined,
)
from pathlib import Path
import json, yaml
from pprint import pprint
from parsers import graphql_parser, openapi_parser
import display
import haralyzer 
from urllib.parse import urlparse
from collections import defaultdict


Exposed_documentation=   Path("wordlists") / "exposed_documentation.txt"
HAR = Path("HarFiles") / "EnumHarr.har"

listOfGraphQLEndpoints=['/graphql','/api','/api/graphql','/graphql/api','/graphql/graphql']
LOGIN_PATHS = ["/login","/api/login","/api/v1/login","/api/v2/login","/auth/login","/api/auth/login","/signin","/api/signin",
    "/authenticate","/api/authenticate","/users/login","/user/login","/account/login","/session","/api/token","/oauth/token",]
methods=['POST','GET','PUT','PATCH']

def discovery(url,usernameA=None,emailA=None,passwordA=None,login_url=None):
    print("[!] Discovering API type...")
    is_graphql,graphql_endpoint=check_graphql(url)
    print(f"is_graphql: {is_graphql}, ")
    if is_graphql:
        # let's try introrspection
        if not login_url:
            login_endpoint=find_login_endpoint(url)
        accountA,_,_=authenticate(url,login_url=login_endpoint,usernameA=usernameA,emailA=emailA,passwordA=passwordA)
        graphql_schema=introspection(graphql_endpoint,accountA.token)
        if graphql_schema:
            print("All good, exiting blackbox with code 0")
            return graphql_schema,login_endpoint
        else:
            print("[!] Attempting HAR extraction...")
            API=extract_HAR(HAR,"GRAPHQL")
            
    else:
        doc=None
        print("[!] No GraphQL detected, assuming REST API...")
        #doc=finding_exposed_specifications(url)
        if doc:
            API= openapi_parser.parse_openapi(doc)
            display.display_endpoints(API)
            return API, None 
        else:
            print("[!] Attempting HAR extraction...")
            API=extract_HAR(HAR,"REST")
            print("----------------------------------")

            return API, None
            
    return None, None

def check_graphql(url):

    payload = {"query": "query{__typename}"}

    for method in methods:
        for endpt in listOfGraphQLEndpoints:
            request_url = url.rstrip('/') + '/' + endpt.lstrip('/')
            response = send_request(method,request_url,json_body=payload)
            if response is None:
                continue
            try:
                data = response.json()
            except ValueError:
                continue
            if (isinstance(data, dict) and isinstance(data.get("data"), dict) and "__typename" in data["data"]):
                print(f"[+] GraphQL endpoint found: {request_url}")
                return True, request_url

    return False, None

def introspection(url,token=None):
    headers = {}
    if token:
        headers = {
            'Authorization': f'Bearer {token}'
        }
    introspection_query="""
query FullSchemaIntrospection {
  __schema {

    queryType {
      name
    }

    mutationType {
      name
    }

    subscriptionType {
      name
    }

    types {
      kind
      name
      description

      fields(includeDeprecated: true) {
        name
        description

        args {
          name
          description
          defaultValue

          type {
            ...TypeRef
          }
        }

        type {
          ...TypeRef
        }
      }

      inputFields {
        name
        description
        defaultValue

        type {
          ...TypeRef
        }
      }

      interfaces {
        ...TypeRef
      }

      enumValues(includeDeprecated: true) {
        name
        description
      }

      possibleTypes {
        ...TypeRef
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name

  ofType {
    kind
    name

    ofType {
      kind
      name

      ofType {
        kind
        name

        ofType {
          kind
          name
        }
      }
    }
  }
}
"""
    graphql_operations = []

    introspection_response = send_graphql_request(
        url,
        query=introspection_query,
        headers=headers
    )

    if introspection_response is None:
        return []

    try:
        introspection_response = introspection_response.json()
    except ValueError:
        return []

    schema = build_client_schema(introspection_response["data"])
    schema = build_client_schema(introspection_response["data"])

    queries = parse_operations(
        schema.query_type,
        "query"
    )

    mutations = parse_operations(
        schema.mutation_type,
        "mutation"
    )

    # subscriptions = parse_operations(
    #     schema.subscription_type,
    #     "subscription"
    # )
    graphql_schema = GraphQLSchema(
        queries=queries,
        mutations=mutations,
        types={}
    )

    return graphql_schema
        
def parse_operations(root_type, operation_type):
    operations = []
    if root_type is None:
        return operations
    for name, field in root_type.fields.items():
        graphql_arguments = []
        graphql_fields = []
        # print(f"\nOperation: {name}")
        # print(f"Operation type: {operation_type}")
        # print(f"Return type: {field.type}")
        # Arguments
        for arg_name, arg in field.args.items():
            default_value = (None if arg.default_value is Undefined else arg.default_value)
            graphql_argument = GraphQLArgument(
                name=arg_name,
                type=str(arg.type),
                required=is_non_null_type(arg.type),
                default_value=default_value
            )
            graphql_arguments.append(graphql_argument)

        # Return fields
        named_type = get_named_type(field.type)
    
        if hasattr(named_type, "fields"):
            for field_name, subfield in named_type.fields.items():
                named_subfield_type = get_named_type(subfield.type)
                if is_scalar_type(named_subfield_type):
                    kind = "SCALAR"
                elif is_enum_type(named_subfield_type):
                    kind = "ENUM"
                elif is_object_type(named_subfield_type):
                    kind = "OBJECT"
                elif is_interface_type(named_subfield_type):
                    kind = "INTERFACE"
                elif is_union_type(named_subfield_type):
                    kind = "UNION"
                else:
                    kind = "UNKNOWN"
    
                graphql_field = GraphQLField(
                    name=field_name,
                    type=str(subfield.type),
                    required=is_non_null_type(subfield.type),
                    description=subfield.description,
                    kind=kind
                    
                )
                graphql_fields.append(graphql_field)

        graphql_operation = GraphQLOperation(
            name=name,
            operation_type=operation_type,
            arguments=graphql_arguments,
            return_types=str(field.type),
            fields=graphql_fields,
            description=field.description
        )

        operations.append(graphql_operation)

    return operations
        
def find_login_endpoint(base_url, paths=None):

    paths = paths or LOGIN_PATHS
    base = base_url.rstrip("/")

    print(f"[!] Searching for a login endpoint on {base}")

    for path in paths:
        login_url = base + path

        response = send_request( method="POST", url=login_url, json_body={})

        if response is None:
            continue

        status = response.status_code

        if status in (404, 405):
            continue

        print(f"    [+] candidate: POST {path} -> HTTP {status}")
        print(f"[+] Selected login endpoint: {login_url}")
        return login_url

    print("[!] No login endpoint found among the common paths.")
    return None


def finding_exposed_specifications(url):
    
    wordlist=loadwordlist()
    for word in wordlist:
        if word.startswith('#'):
            continue
        test_url=url.rstrip('/') + '/' + word.lstrip('/')
        response= send_request(method='GET', url=test_url)
        if response is None:
            continue
        if response.status_code in (404,405):
            continue
        text=response.text
        data,ext=parse_spec(text)
        if data is None or ('openapi' not in data and 'swagger' not in data):
            continue
        print(f"Potential documentation candidate {test_url}")
        return data 
    return None

def parse_spec(text):

    try:
        data = json.loads(text)
        return data, 'json'
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data, 'yaml'
    except yaml.YAMLError:
        pass
    return None, None


def loadwordlist():
    keywords = set({})
    try:
        with Exposed_documentation.open("r",encoding="utf-8") as file:
            for line in file:
                keyword = line.strip().lower()

                if keyword and not keyword.startswith("#"):
                    keywords.add(keyword)

    except OSError as exc:
        print(
            f"[!] Unable to read {Exposed_documentation}: {exc}. "
            "Default authentication keywords will be used."
        )

    return keywords

STATIC_SEGMENTS = {
    "login", "signin", "sign-in", "register", "email", "password",
    "debug", "_debug", "me", "health", "status", "search",
    "createdb"
}

LOGIN_SEGMENTS = {
    "login", "signin", "sign-in", "authenticate", "authentication",
    "token", "session"
}


# -----------------------------------------------------------------------------
# PUBLIC ENTRY POINT
# -----------------------------------------------------------------------------

def extract_HAR(har_file, case=None):
    """Reconstruct Endpoint[] from observed HAR traffic."""

    if case == "REST":
        print("[!] Initializing HAR enumeration for REST API...")
    elif case == "GRAPHQL":
        print("[!] Initializing HAR enumeration for GRAPHQL...")

    try:
        with open(har_file, "r", encoding="utf-8") as f:
            har_data = json.load(f)
        har = haralyzer.HarParser(har_data)
    except Exception as e:
        print(f"[!] Could not read HAR file: {e}")
        return []

    print("[+] HAR file successfully loaded")

    observations = extract_observations(har)

    # Learn concrete object values from all captured JSON traffic.
    # Example: "name1" -> "username", "bookTitle56" -> "book_title".
    value_hints = collect_value_hints(observations)

    # Pairwise inference remains only as a fallback when response/body evidence
    # does not tell us the parameter name.
    pairwise_hints = collect_pairwise_path_hints(observations)
    positional_hints = collect_positional_hints(observations, value_hints)

    grouped = defaultdict(list)

    for request in observations:
        template, path_parameters = generalize_path(
            request["path"],
            value_hints,
            pairwise_hints,
            positional_hints,
        )

        enriched = dict(request)
        enriched["template"] = template
        enriched["path_parameters"] = path_parameters
        grouped[(request["method"], template)].append(enriched)

    endpoints = []

    for (method, template), operation_observations in grouped.items():
        best = select_best_observation(operation_observations)
        endpoints.append(build_endpoint(method, template, operation_observations, best))

    endpoints.sort(key=lambda endpoint: (endpoint.path, endpoint.method))

    print("\n[+] HAR Endpoints:")
    for endpoint in endpoints:
        objects = ", ".join(endpoint.object_candidates) if endpoint.object_candidates else "-"
        auth = "Protected" if endpoint.authentication.required else "Public/Unknown"
        print(f"    {endpoint.method:<6} {endpoint.path:<35} auth={auth:<14} objects={objects}")

    return endpoints


# -----------------------------------------------------------------------------
# RAW HAR EXTRACTION
# -----------------------------------------------------------------------------

def extract_observations(har):
    observations = []

    for page in har.pages:
        for entry in page.entries:
            method = entry.request.get("method", "GET").upper()
            url = entry.request.get("url", "")
            path = urlparse(url).path or "/"

            query_parameters = [
                {"name": param.get("name"), "value": param.get("value")}
                for param in entry.request.get("queryString", [])
                if param.get("name")
            ]

            request_body, request_content_type = extract_request_body(entry)
            response_status, response_body, response_content_type = extract_response(entry)
            headers = normalize_headers(entry.request.get("headers", []))

            observation = {
                "method": method,
                "path": path,
                "query_parameters": query_parameters,
                "request_body": request_body,
                "request_content_type": request_content_type,
                "response_status": response_status,
                "response_body": response_body,
                "response_content_type": response_content_type,
                "headers": headers,
            }

            observations.append(observation)

            print(f"{method} {path}")
            print(f"     Status {response_status}")
            if query_parameters:
                print(f"     Query {query_parameters}")
            if request_body is not None:
                print(f"     Request Body {request_body}")
            if response_body is not None:
                print(f"     Response Body {response_body}")

    return observations


def extract_request_body(entry):
    post_data = entry.request.get("postData")
    if not post_data:
        return None, None

    mime_type = post_data.get("mimeType", "")
    text = post_data.get("text")

    if not text:
        return None, mime_type or None

    if "json" in mime_type.lower():
        try:
            return json.loads(text), mime_type
        except json.JSONDecodeError:
            return None, mime_type

    return None, mime_type or None


def extract_response(entry):
    status = entry.response.get("status")
    content = entry.response.get("content", {})
    mime_type = content.get("mimeType", "")
    text = content.get("text")
    body = None

    if text and "json" in mime_type.lower():
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = None

    return status, body, mime_type or None


def normalize_headers(headers):
    return {
        header.get("name", "").lower(): header.get("value", "")
        for header in headers
        if header.get("name")
    }


# -----------------------------------------------------------------------------
# PATH RECONSTRUCTION
# -----------------------------------------------------------------------------

def collect_value_hints(observations):
    """Map observed scalar values to field names found in JSON bodies."""
    hints = defaultdict(list)

    for request in observations:
        collect_json_values(request.get("request_body"), hints)
        collect_json_values(request.get("response_body"), hints)

        for param in request.get("query_parameters", []):
            value = param.get("value")
            name = param.get("name")
            if value is not None and name:
                add_hint(hints, value, name)

    return hints


def collect_json_values(data, hints):
    if isinstance(data, dict):
        for key, value in data.items():
            if is_scalar(value):
                add_hint(hints, value, key)
            else:
                collect_json_values(value, hints)

    elif isinstance(data, list):
        for item in data:
            collect_json_values(item, hints)


def add_hint(hints, value, name):
    if value is None or isinstance(value, bool):
        return

    value = str(value)
    name = str(name)

    if not value or not name:
        return

    if name not in hints[value]:
        hints[value].append(name)


def is_scalar(value):
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def collect_pairwise_path_hints(observations):
    """Fallback: learn variable positions from similar concrete paths, across methods too."""
    hints = defaultdict(list)
    paths = list(dict.fromkeys(request["path"] for request in observations))

    for i in range(len(paths)):
        for j in range(i + 1, len(paths)):
            parts1 = split_path(paths[i])
            parts2 = split_path(paths[j])

            if len(parts1) != len(parts2):
                continue

            differences = [index for index in range(len(parts1)) if parts1[index] != parts2[index]]

            if len(differences) != 1:
                continue

            index = differences[0]
            if index == 0:
                continue

            value1 = parts1[index]
            value2 = parts2[index]

            if is_static_segment(value1) or is_static_segment(value2):
                continue

            # Both values are evidence that this position can vary.
            if index not in hints[tuple(parts1[:index])]:
                hints[tuple(parts1[:index])].append(index)

    return hints




def collect_positional_hints(observations, value_hints):
    """Learn a parameter name for a path position from sibling values with JSON evidence."""
    hints = {}

    for request in observations:
        parts = split_path(request["path"])

        for index, value in enumerate(parts):
            if index == 0 or is_static_segment(value):
                continue

            names = value_hints.get(value, [])
            if not names:
                continue

            key = (tuple(parts[:index]), index)
            hints.setdefault(key, choose_parameter_name(names))

    return hints


def generalize_path(path, value_hints, pairwise_hints, positional_hints):
    parts = split_path(path)
    parameters = []

    for index, value in enumerate(parts):
        if index == 0 or is_static_segment(value):
            continue

        names = value_hints.get(value, [])

        if names:
            name = choose_parameter_name(names)
            parts[index] = "{" + name + "}"
            parameters.append({"name": name, "value": value, "index": index})
            continue

        # Fallback: position was seen varying in a similar path family.
        prefix = tuple(parts[:index])
        if index in pairwise_hints.get(prefix, []):
            name = positional_hints.get((tuple(parts[:index]), index)) or infer_name_from_resource(parts, index)
            parts[index] = "{" + name + "}"
            parameters.append({"name": name, "value": value, "index": index})

    template = "/" + "/".join(parts) if parts else "/"
    return template, parameters


def choose_parameter_name(names):
    """Prefer explicit identifier-like names, otherwise use the first observed key."""
    priorities = ("username", "user_id", "userid", "book_title", "id", "uuid", "slug", "key", "reference")

    lowered = {name.lower(): name for name in names}

    for priority in priorities:
        if priority in lowered:
            return lowered[priority]

    for name in names:
        lowered_name = name.lower()
        if lowered_name.endswith("id") or lowered_name.endswith("_id"):
            return name

    return names[0]


def infer_name_from_resource(parts, index):
    """Safe fallback when only path-shape evidence exists."""
    resource = parts[index - 1].lower() if index > 0 else "param"

    if resource.endswith("s") and len(resource) > 1:
        resource = resource[:-1]

    if resource in {"user", "users"}:
        return "username"
    if resource in {"book", "books"}:
        return "book_title"

    return resource + "_id" if resource not in {"v1", "v2", "api"} else "param"


def split_path(path):
    return [part for part in path.strip("/").split("/") if part]


def is_static_segment(value):
    return value.lower() in STATIC_SEGMENTS


# -----------------------------------------------------------------------------
# MODEL BUILDING
# -----------------------------------------------------------------------------

def build_endpoint(method, template, observations, best):
    path_examples = {}

    for request in observations:
        for parameter in request.get("path_parameters", []):
            path_examples.setdefault(parameter["name"], parameter["value"])

    path_parameters = [
        Parameter(
            name=name,
            location="path",
            required=True,
            param_type="string",
            schema={},
            example=value,
            is_object_candidate=True,
        )
        for name, value in path_examples.items()
    ]

    query_parameters = build_query_parameters(best.get("query_parameters", []))
    object_candidates = [parameter.name for parameter in path_parameters]

    return Endpoint(
        path=template,
        method=method,
        operation_id=None,
        summary=None,
        description=None,
        tags=[],
        parameters=path_parameters + query_parameters,
        request_body=build_request_body(
            best.get("request_body"),
            best.get("request_content_type"),
        ),
        authentication=infer_authentication(observations),
        responses=build_response(
            best.get("response_status"),
            best.get("response_body"),
            best.get("response_content_type"),
        ),
        object_candidates=object_candidates,
        is_potential_login_endpoint=is_potential_login(template),
    )


def build_query_parameters(query_parameters):
    return [
        Parameter(
            name=param["name"],
            location="query",
            required=False,
            param_type="string",
            schema={},
            example=param.get("value"),
            is_object_candidate=False,
        )
        for param in query_parameters
    ]


def build_request_body(body, content_type=None):
    if body is None:
        return None

    properties = {}

    if isinstance(body, dict):
        for name, value in body.items():
            properties[name] = {"example": value}

    return RequestBody(
        required=True,
        content_types=[content_type] if content_type else [],
        schema={},
        properties=properties,
    )


def build_response(status, body, content_type=None):
    return Response(
        status_code=str(status) if status is not None else None,
        description=None,
        content_types=[content_type] if content_type else [],
        properties=body if isinstance(body, dict) else {},
        raw=body if isinstance(body, dict) else {},
    )


# -----------------------------------------------------------------------------
# AUTHENTICATION INFERENCE
# -----------------------------------------------------------------------------

def has_auth(request):
    headers = request.get("headers", {})
    return bool(headers.get("authorization") or headers.get("cookie"))


def observed_auth_schemes(request):
    headers = request.get("headers", {})
    schemes = []

    authorization = headers.get("authorization", "")
    if authorization:
        scheme = authorization.split(" ", 1)[0].lower() if " " in authorization else "authorization"
        schemes.append(scheme)

    if headers.get("cookie"):
        schemes.append("cookie")

    return schemes


def infer_authentication(observations):
    """
    HAR cannot prove OpenAPI security requirements perfectly.

    Strong evidence:
      unauthenticated 401/403 + authenticated 2xx.

    Useful fallback:
      authenticated traffic exists and we never observed a successful unauthenticated call.
    """
    unauth_denied = any(
        not has_auth(request) and request.get("response_status") in (401, 403)
        for request in observations
    )

    auth_success = any(
        has_auth(request) and is_successful(request)
        for request in observations
    )

    any_auth = any(has_auth(request) for request in observations)
    unauth_success = any(
        not has_auth(request) and is_successful(request)
        for request in observations
    )

    required = (unauth_denied and auth_success) or (any_auth and not unauth_success)

    schemes = []
    if required:
        for request in observations:
            if has_auth(request):
                for scheme in observed_auth_schemes(request):
                    if scheme not in schemes:
                        schemes.append(scheme)

    return Authentication(required=required, schemes=schemes)


def is_potential_login(path):
    segments = {segment.lower() for segment in split_path(path)}
    return bool(segments & LOGIN_SEGMENTS)


# -----------------------------------------------------------------------------
# BEST OBSERVATION SELECTION
# -----------------------------------------------------------------------------

def observation_score(request):
    status = request.get("response_status")
    score = 0

    if status is not None and 200 <= status < 300:
        score += 100
    elif status is not None and 300 <= status < 400:
        score += 50
    elif status in (401, 403):
        score += 10

    if request.get("response_body") is not None:
        score += 5
    if request.get("request_body") is not None:
        score += 2

    return score


def select_best_observation(observations):
    if not observations:
        return None
    return max(observations, key=observation_score)


def is_successful(request):
    status = request.get("response_status")
    return status is not None and 200 <= status < 300