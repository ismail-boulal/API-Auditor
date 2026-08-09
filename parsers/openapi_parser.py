from prance import ResolvingParser

from core.models import (
    Endpoint,
    Parameter,
    RequestBody,
    Authentication,
    Response
)

def parse_openapi(openapi_spec):
    http_methods = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace"
    }
    print("[!] OpenAPI parser is called")
    parser = ResolvingParser(openapi_spec)
    spec = parser.specification
    endpoints = []
    paths = spec.get("paths", {})
    for path, path_items in paths.items():
        path_parameters = path_items.get("parameters", [])
        for method, details in path_items.items():
            if method.lower() not in http_methods:
                continue
            operation_parameters = details.get("parameters",[])
            all_parameters = (path_parameters + operation_parameters)

            parameters = []
            object_candidates = []
            
            for p in all_parameters:
                name = p.get("name")
                location = p.get("in")

                parameter = Parameter(
                    name=name,
                    location=location,
                    required=p.get( "required",False ),
                    param_type=p.get("schema", {}).get("type"),
                    schema=p.get("schema",{} ),
                    example=p.get("example")
                )

                if location == "path":
                    parameter.is_object_candidate = True
                    object_candidates.append(name)
                parameters.append(parameter)

            security = details.get("security",spec.get("security",[] ))
            security_schemes = []
            
            for requirement in security:
                security_schemes.extend(
                    requirement.keys()
                )

            authentication = Authentication(
                required=len(security) > 0,
                schemes=security_schemes
            )
            request_body = None
            
            if "requestBody" in details:
                raw_body = details["requestBody"]
                content = raw_body.get("content", {})

                
                content_type = "application/json" if "application/json" in content else next(iter(content), None)

                
                json_schema = content.get(content_type, {}).get("schema", {}) if content_type else {}

                
                extracted_properties = _extract_properties(json_schema)

                request_body = RequestBody(
                    required=raw_body.get("required", False),
                    content_types=list(content.keys()),
                    schema=content,
                    properties=extracted_properties   
                )
            raw_responses = details.get("responses", {})
            status_code, success_response = _pick_success_response(raw_responses)

            if success_response:
                content = success_response.get("content", {})
                content_type = "application/json" if "application/json" in content else next(iter(content), None)
                json_schema = content.get(content_type, {}).get("schema", {}) if content_type else {}

                response_obj = Response(
                    status_code=status_code,
                    description=success_response.get("description"),
                    content_types=list(content.keys()),
                    properties=_extract_properties(json_schema),
                    raw=raw_responses
                )
            else:
                response_obj = Response(raw=raw_responses)
            endpoint = Endpoint(
                path=path,
                method=method.upper(),
                operation_id=details.get("operationId"),
                summary=details.get("summary"),
                description=details.get("description"),
                tags=details.get("tags",[]),
                parameters=parameters,
                request_body=request_body,
                authentication=authentication,
                responses=response_obj,
                object_candidates=object_candidates
            )
            endpoints.append(endpoint)
    return endpoints

def _extract_properties(json_schema):
    if not isinstance(json_schema, dict):
        return {}

    schema_type = json_schema.get("type")

    # NOUVEAU : si le schema racine est un tableau, descendre dans items
    if schema_type == "array":
        items_schema = json_schema.get("items", {})
        return _extract_properties(items_schema)

    properties = json_schema.get("properties", {})
    result = {}
    for name, prop_schema in properties.items():
        prop_type = prop_schema.get("type")
        if prop_type == "object":
            result[name] = {"type": "object", "properties": _extract_properties(prop_schema)}
        elif prop_type == "array":
            items_schema = prop_schema.get("items", {})
            items_type = items_schema.get("type")
            if items_type == "object":
                result[name] = {"type": "array", "items": _extract_properties(items_schema)}
            else:
                # NOUVEAU : items peut avoir des properties sans type=='object' explicite
                nested = _extract_properties(items_schema)
                if nested:
                    result[name] = {"type": "array", "items": nested}
                else:
                    result[name] = {"type": "array", "items_type": items_type}
        else:
            result[name] = {"type": prop_type}
    return result

def _pick_success_response(responses: dict):
    if "200" in responses:
        return "200", responses["200"]
    for status_code, resp in responses.items():
        if status_code.startswith("2"):
            return status_code, resp
    return None, None
