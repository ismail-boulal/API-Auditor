from core.graphql_client import *
from pathlib import Path
import json
from pprint import pprint
from itertools import product
from core.models import Finding

HAR_A = Path("HarFiles") / "HarQLA.har"
HAR_B = Path("HarFiles") / "HarQLB.har"


def accessControlQL(graphql_schema,accounts,base_url):
    finding=[]
    print("[!] BolaQL initializing...")
    if graphql_schema is None:
        print("[-] GraphQL schema is empty! Aborting...")
        return None
    accountA = accountB = accountAD = None
    
    for account in accounts:
        if account is None:
            continue
        if account.Label == 'A':
            accountA=account
        elif account.Label == 'B':
            accountB=account
            
    if accountA.token:
        headerA = {
            'Authorization': f'Bearer {accountA.token}'
        }
    if accountB.token:
        headerB = {
            'Authorization': f'Bearer {accountB.token}'
        }

    Qry_url= base_url.rstrip('/') + '/' + 'graphql'.lstrip('/') # Hardcoded
    
    userA_values,remaining_values=extractUserValues(graphql_schema,Qry_url,accountA,HAR_A)
    userB_values,remaining_values=extractUserValues(graphql_schema,Qry_url,accountB,HAR_B)
    
    print("User A values:")
    print(json.dumps(userA_values, indent=4))

    print("\nUser B values:")
    print(json.dumps(userB_values, indent=4))
    pprint(f"Remaining: {remaining_values}")

    excluded_operation=excluded_operations(graphql_schema,remaining_values) # those queries in which no arg  is found 
    
    queries = graphql_schema.queries
    mutations = graphql_schema.mutations
    operations = [queries, mutations]
    
    bfla_candidates=calculate_bfla_score(operations)
    bfla_candidates = { k: v for k, v in bfla_candidates.items() if v > 0}
    bfla_candidates = dict(sorted(bfla_candidates.items(), key=lambda item: item[1],reverse=True))

    test_bola=testAccess(graphql_schema,excluded_operation,userB_values,headerA,Qry_url,userA_values)
    test_bfla=testAccess(graphql_schema,excluded_operation,userA_values,headerA,Qry_url)
    
    
    bfla_operations = {k:v for k,v in test_bfla.items() if k.lower() in bfla_candidates}
    bola_operations = set(test_bola.keys()) #  set(test_bola.keys())


    producer_queries, _ = indentify_producer_queries(graphql_schema.queries,Qry_url,headerA)
    producer_queries = {q.name.lower() for q in producer_queries}
    bfla_operations = { op:v for op,v in bfla_operations.items() if op.lower() not in producer_queries}
    bola_operations = {op:v for op,v in test_bola.items() if op.lower() not in producer_queries}
    
    print("BOLA")
    pprint(bola_operations)
    for k,v in bola_operations.items():
        bola_finding=Finding(
            vulnerability="BOLA-GraphQL",
            endpoint=k,
            confidence='Confirmed',
            evidence=v
        )
        finding.append(bola_finding)
    print("BFLA")
    pprint(bfla_operations)
    for k,v in bfla_operations.items():
        bfla_finding=Finding(
            vulnerability="BFLA-GraphQL",
            endpoint=k,
            confidence='Confirmed',
            evidence=v
        )
        finding.append(bfla_finding)
            
    return finding

def testAccess(graphql_schema,excluded_operation,user_values,headerA,Qry_url,other_values=None):
    successful_operations={}
     
    queries = graphql_schema.queries
    mutations = graphql_schema.mutations
    operations = [queries, mutations]
    
    for operation in operations:
        for qm in operation: # work with all the queries first and then move to all the mutations
            if qm in excluded_operation or qm.name == 'login' or not qm.arguments: # whether it's a queries or mutations, loop through all their operations 
                continue # and if we don't have no arguments for a certain operation, or it's a login mutation, skip it 
            query_shape=build_graphql_operation(qm.operation_type,qm.name,qm.arguments,qm.fields)
            print(query_shape)
            variables=extractVariables(qm.arguments,user_values)
            
            #print(variables)
            
            # if len(variables) > 1:
            #     print("[!] Multi-object operation Identified! ")
            #     other_variables=extractVariables(qm.arguments,other_values)
            #     all_possible_variables=combine_dicts_unique(variables,other_variables)
                
            #     for possible_variable in all_possible_variables:
            #         pprint(possible_variable)
            #         ans=send_graphql_request(Qry_url,query_shape,possible_variable,headerA,proxy='127.0.0.1:8080')
            #         valid=analyse_response(ans)
            #         if valid:
            #             successful_operations[qm.name]=ans.json()
            
            pprint(variables)
            public=send_graphql_request(Qry_url,query_shape,variables) # if the operation is successfull without authorization, it's public ignore it 
            if analyse_response(public):
                print(f"[!] Public operation : {qm.name}")
                continue
            ans=send_graphql_request(Qry_url,query_shape,variables,headerA)
            valid=analyse_response(ans)
            if valid:
                successful_operations[qm.name]=ans.json()
            
            
    #pprint(successful_operations)
    
    return successful_operations



        



def extractUserValues(graphql_schema,Qry_url,account,har):
    if account.token:
        header = {
            'Authorization': f'Bearer {account.token}'
        }
    # Those are the arguments that all queries and mutations need 
    needed_objects=identify_needed_objects(graphql_schema)
    # find queries that don't need arguments
    producer_queries,found_values=indentify_producer_queries(graphql_schema.queries,Qry_url,header)
    # call those queries and take everything we can
    values,remaining_values=assign_values(needed_objects,found_values)
    # the rest look in the HAR files
    har_values,remaining_values=extract_har_values(har,remaining_values)
    values.update(har_values)
    # the rest, is either a user attribute, or will be a random value
    values,remaining_values=deal_with_the_rest(remaining_values,account,values)
    
    
    return values,remaining_values

def extractVariables(arguments, values):
    variables = {}

    for arg in arguments:
        if arg.name in values:
            val = values[arg.name]
            variables[arg.name] = val[0] if isinstance(val, list) else val

    return variables

def excluded_operations(graphql_schema, remaining_values):
    excluded_operations = []
    queries = graphql_schema.queries
    mutations = graphql_schema.mutations
    operations = [queries, mutations]
    for operation in operations:
        for qm in operation:
            for arg in qm.arguments:
                if arg.name in remaining_values:
                    excluded_operations.append(qm)
                    break
    print(f"Operations excluded: {[op.name for op in excluded_operations]}")
    return excluded_operations

def identify_needed_objects(graphql_schema):
    needed=[]
    for query in graphql_schema.queries:
        for argument in query.arguments:
            needed.append(argument.name)
    for mutation in graphql_schema.mutations:
        for argument in mutation.arguments:
            needed.append(argument.name)
            
    return sorted(set(needed))

def indentify_producer_queries(queries,url,header):
    #print("[!] Possible producer queries")
    producer_queries=[]
    found_values={}
    for i,query in enumerate(queries):
        if not query.arguments:
            #print(f"[{i}] name: {query.name}")
            producer_queries.append(query)
            query_operation=build_graphql_operation(operation_type=query.operation_type,operation_name=query.name,fields=query.fields)
            #print(query_operation)
            ans=send_graphql_request(url=url,query=query_operation,headers=header)  
            found_values[query.name]=ans.json().get('data').get(query.name)
            
           
    return producer_queries,found_values

def assign_values(needed_values, found_values):
    values = {}
    for needed_value in needed_values:
        needed = needed_value.lower()
        for operation, vals in found_values.items():
            if isinstance(vals, list):
                for item in vals:
                    for k, v in item.items():
                        key = k.lower()
                        if key in ["id", "name"]:
                            continue
                        if needed == key or needed.endswith(key) or key.endswith(needed):
                            values.setdefault(needed_value, [])
                            if v not in values[needed_value]:
                                values[needed_value].append(v)
            elif isinstance(vals, dict):
                for k, v in vals.items():
                    key = k.lower()
                    if key in ["id", "name"]:
                        continue
                    if needed == key or needed.endswith(key) or key.endswith(needed):
                        values.setdefault(needed_value, [])
                        if v not in values[needed_value]:
                            values[needed_value].append(v)

    # collapse: if we only found ONE value for a key, keep it as a plain scalar
    # (this is what keeps the rest of your pipeline working unchanged)
    for k in values:
        if len(values[k]) == 1:
            values[k] = values[k][0]

    remaining_values = []
    for needed in needed_values:
        if needed not in values:
            remaining_values.append(needed)

    return values, remaining_values


def extract_har_values(Har,remaining_values=None):
    har_values = {}


    with open(Har, "r", encoding="utf-8") as f:
        har_data = json.load(f)

    for entry in har_data["log"]["entries"]:
        post_data = entry["request"].get("postData", {})
        text = post_data.get("text")

        if not text:
            continue

        body = json.loads(text)

        query = body.get("query", "")
        variables = body.get("variables", {})
        for remaining_value in remaining_values:
            if remaining_value in query:
                #print(f"value: {remaining_value} found !")
                if variables:
                    old_key = next(iter(variables))
                    variables[remaining_value] = variables.pop(old_key)
                    remaining_values.remove(remaining_value)
        #print(f"query: {query}")
        #print(f"variables: {variables}")
        har_values.update(variables)

    return har_values,remaining_values

def deal_with_the_rest(remaining_values, account, values):
    still_remaining = []
    for remaining_value in remaining_values:
        if hasattr(account, remaining_value):
            values[remaining_value] = getattr(account, remaining_value)
        elif remaining_value.lower().endswith('id'):
            still_remaining.append(remaining_value)
        else:
            values[remaining_value] = 'random_text'
    return values, still_remaining


        
def calculate_bfla_score(operations):

    BFLA_KEYWORDS = {}
    with open("wordlists/privileged_operations.txt", "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            keyword, weight = line.split(":")
            BFLA_KEYWORDS[keyword.lower()] = int(weight)

    bfla_scores = {}

    for operation in operations:
        for qm in operation:
            operation_name = qm.name.lower()
            score = 0
            for keyword, weight in BFLA_KEYWORDS.items():
                if keyword in operation_name:
                    score += weight
            bfla_scores[operation_name] = score

    return bfla_scores

def analyse_response(response):
    body = response.json()
    if "errors" in body and not body.get("data"):
        return False
    return True
    
    




def combine_dicts_unique(*dicts):
    keys = list(dicts[0].keys())
    
    value_lists = [
        [(d[key], dict_index) for dict_index, d in enumerate(dicts)]
        for key in keys
    ]
    
    seen = set()
    result = []
    
    for combo in product(*value_lists):
        values = [v for v, origin in combo]
        origins = [origin for v, origin in combo]
        
        # Skip ONLY if every value came from dict index 1 (the second dict)
        if set(origins) == {1}:
            continue
        
        candidate = dict(zip(keys, values))
        fingerprint = frozenset(candidate.items())
        
        if fingerprint not in seen:
            seen.add(fingerprint)
            result.append(candidate)
    
    return result   


    
    
