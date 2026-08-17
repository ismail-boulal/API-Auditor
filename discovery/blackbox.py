# Version: 1
# script objective: be able to enumerate an API with only an url provided and transform it into a commun endpoint object
from core.http_client import send_request
from core.graphql_client import send_graphql_request
from core.models import GraphQLField, GraphQLArgument, GraphQLOperation, GraphQLSchema  
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


listOfGraphQLEndpoints=['/graphql','/api','/api/graphql','/graphql/api','/graphql/graphql']
LOGIN_PATHS = ["/login","/api/login","/api/v1/login","/api/v2/login","/auth/login","/api/auth/login","/signin","/api/signin",
    "/authenticate","/api/authenticate","/users/login","/user/login","/account/login","/session","/api/token","/oauth/token",]
methods=['POST','GET','PUT','PATCH']

def discovery(url,usernameA=None,emailA=None,passwordA=None):
    print("[!] Discovering API type...")
    is_graphql,graphql_endpoint=check_graphql(url,usernameA,emailA,passwordA)
    print(f"is_graphql: {is_graphql}, ")
    if is_graphql:
        # let's try introrspection
        login_endpoint=find_login_endpoint(url)
        accountA,_,_=authenticate(url,login_url=login_endpoint,usernameA=usernameA,emailA=emailA,passwordA=passwordA)
        graphql_schema=introspection(graphql_endpoint,accountA.token)
        if graphql_schema:
            print("All good, exiting blackbox with code 0")
            return graphql_schema,login_endpoint
            
        
    return None, []

def check_graphql(url,usernameA=None,emailA=None,passwordA=None):

    payload = {"query": "query{__typename}"}

    for method in methods:
        for endpt in listOfGraphQLEndpoints:
            request_url = url.rstrip('/') + '/' + endpt.lstrip('/')
            response = send_request(
                method,
                request_url,
                json_body=payload
            )
            if response is None:
                continue
            try:
                data = response.json()
            except ValueError:
                continue
            if (
                isinstance(data, dict)
                and isinstance(data.get("data"), dict)
                and "__typename" in data["data"]
            ):
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

            default_value = (
                None
                if arg.default_value is Undefined
                else arg.default_value
            )

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

        response = send_request(
            method="POST",
            url=login_url,
            json_body={},
        )

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