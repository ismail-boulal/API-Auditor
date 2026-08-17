# core/graphql_client.py

import requests
import json

def send_graphql_request(url,query,variables=None,headers=None,operation_name=None,cookies=None,timeout=600,proxy=None):
   
    payload = {"query": query}

    if variables is not None:
        payload["variables"] = variables

    if operation_name is not None:
        payload["operationName"] = operation_name
    proxies=get_proxies(proxy)
    try:
        response = requests.post(
            url=url,
            headers=headers,
            json=payload,
            cookies=cookies,
            timeout=timeout,
            verify=True,
            allow_redirects=False,
            proxies=proxies

        )

        return response

    except requests.RequestException as e:
        print(f"[!] GraphQL request failed: {e}")
        return None
    
def build_graphql_operation(operation_type="query",operation_name=None,arguments=None,fields=None,use_variables=True):

    arguments = arguments or []
    fields = fields or []
    variable_definitions = []

    if use_variables:
        for arg in arguments:
            variable_definitions.append(
                f"${arg.name}: {arg.type}"  # e.g. $ticketId: ID!
            )

    variables_wrapper = ""

    if variable_definitions:
        variables_wrapper = ("(" + ", ".join(variable_definitions) + ")" ) # e.g. ($tickerId: ID!, $operationID: ID!)

    argument_calls = []

    if use_variables:
        for arg in arguments:
            argument_calls.append(f"{arg.name}: ${arg.name}")

    arguments_wrapper = ""

    if argument_calls:
        arguments_wrapper = ("(" + ", ".join(argument_calls)  + ")")# e.g. (ticketId: $ticketId)

    fields_string = ""

    if fields:
        fields_string = "\n        ".join(
            field.name if hasattr(field, "name") else field
            for field in fields
            if not hasattr(field, "kind") or field.kind in ["SCALAR", "ENUM"]
        )

    operation_header = operation_type

    if variables_wrapper:
        operation_header += variables_wrapper


    operation_call = operation_name or ""

    if arguments_wrapper:
        operation_call += arguments_wrapper

    if fields_string:

        return f"""
{operation_header} {{
    {operation_call} {{
        {fields_string}
    }}
}}
""".strip()

    else:
        return f"""
{operation_header} {{
    {operation_call}
}}
""".strip()

def get_proxies(proxy):
    """Convertit une string proxy en dict pour requests. Retourne None si proxy est None/vide."""
    if not proxy:
        return None
    return {
        "http": proxy,
        "https": proxy
    }
