# This is the main BOLA script that we gonna implement to code bola vulnerability, so BOLA is when user A can access user B resources;
# we have already created an Endpoint object for each path that have the necessary informations, and we have also created in the same manner the account object;
# so BOLA engine needs to know where is the path susceptible to be vulnerable to BOLA; 
# and BOLA engine also needs to have accounts to it can test the cross requests;
# for requests we already implemented the requests script, so let's call it;
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

# these are the top indicators that tha path might have BOLA 
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

# BOLA ENGINE VERSION: 1 

def bola(endpoints,accounts,url):
    accountA=accounts[0]
    accountB=accounts[1]
    intial_bola_endpoints = []
    findings=[]
    display_bola_header()
    

    # print("[!] BOLA ENGINE REACHED")
    print("[!] Potential BOLA vulnerable paths:")
    
    # find the highly potential BOLA endpoint
    for endpoint in endpoints:
        if endpoint.object_candidates and endpoint.method == "GET":
            print(f"\t{endpoint.method}       {endpoint.path}")
            intial_bola_endpoints.append(endpoint)
            
    bola_endpoints=find_bola_endpoints(intial_bola_endpoints)
    bola_endpoints.sort(key=lambda item: item[0], reverse=True)
    
    
    # now for each path of those paths, we make a test 
    for score, bola_endpoint in bola_endpoints: 
        print("--------------------------------------------------------\n\n")
        request_url=url+bola_endpoint.path
        #print(f"\tSCORE={score}  URL={request_url}")
        display_candidate(score, bola_endpoint.method, bola_endpoint.path)
        segments=request_url.split('/')
        index=find_objID(segments)
        print(f"Index: {index}")
        
       
        userAendpoint=substitute_objID(accountA,segments[:],index,bola_path=request_url,Har_file=HAR_A)    
        userBendpoint=substitute_objID(accountB,segments[:],index,bola_path=request_url,Har_file=HAR_B)
        
        print(f"\tuserA endpoint: {userAendpoint}\n\tuserB endpoint: {userBendpoint}")
        
        
        try:
            baseA=make_normal_request(account=accountA,url=userAendpoint)
            baseB=make_normal_request(account=accountB,url=userBendpoint)
            print(f"\tresponse A: {baseA}\n\tresponseB: {baseB}")
            
        except Exception as e:
            print(f"error: [{e}]")
            continue
        if baseA.status_code == 200 and baseB.status_code == 200:
            print("normal requests were succesful")
            print("initializing cross requests")
            crossA=make_bola_request(accountA,accountB,userBendpoint)
            crossB=make_bola_request(accountB,accountA,userAendpoint)
            if crossA.status_code == 200 and crossA.text == baseB.text:
                display_result(True, bola_endpoint.path, accountA.Label, accountB.Label)
                display_bodies(crossA.text, baseB.text, accountA.Label, accountB.Label)
                # print(f"\t[VULNERABLE] {accountA.Label} accessed {accountB.Label}'s object — bodies match")
                # show_bodies(crossA.text, baseB.text)
                finding= Finding(
                    vulnerability="BOLA",
                    endpoint=bola_endpoint,
                    evidence={
                        "account":accountA,
                        "status_code":crossA.status_code,
                        "base_response_body":baseB.text,
                        "cross_response_body":crossA.text
                    }
                )
                findings.append(finding)
                
            else:
                display_result(False, bola_endpoint.path, accountA.Label, accountB.Label)
            
    
            
    return findings


def find_bola_endpoints(initial_bola_endpoints):
   
    print("[!] Identifying BOLA endpoints url:")
    wordlist=loadwordlist() 
    bola_endpoints = []
    
    # take the object identifiers
    for obj_id in initial_bola_endpoints:
        score=0
        sp_obj_id=obj_id.path.split('/')
        for obj in sp_obj_id:
            if obj.startswith('{') and obj.endswith('}'):
                obj = obj.strip('{}')
                if obj.lower() in BOLA_TOP:
                    score+=10
                elif obj.lower().endswith('id'):
                    score+=8
                elif obj.lower() in wordlist:
                    score+=5
        if score>0:            
            bola_endpoints.append((score,obj_id))
            
    return bola_endpoints

def loadwordlist():
    keywords = set({})
    try:
        with BOLA_Object_Identifier_wordlist.open(
            "r",
            encoding="utf-8",
        ) as file:
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


# This function is for each endpoint in endpoints and depends if we passed account A or B 
def make_normal_request(account, url):
    print(f"sending request as user {account.Label}")
    headers = {
        "Authorization": f"Bearer {account.token}",
        "Content-Type": "application/json",
    }
    ans = send_request('GET', url=url, headers=headers)   
    return ans

    


# This functions will take the path /path/{obj} and substitute the {obj} with the value 
def find_objID(segments):
    for i, seg in enumerate(segments):
        if seg.startswith('{') and seg.endswith('}'):
            return i          
    return None         

def substitute_objID(account,segments,index,bola_path,Har_file):
    #print("[!] substiture_objID is called")
    object = segments[index].strip('{}')
    
    if object == "username":
        segments[index]=account.username
              
    elif object =="email":
        segments[index]=account.email     
            
    elif object.lower().endswith("id"):
        
        id = retrieve_id(Har_file,bola_path)
        segments[index]=id     

    url="/".join(segments)  
    
    return url 

"""
Here we have a new problem, we want to take each user's resource ID, but how? in a browser a simple refresh/burp
intercept will do the work, in python the story is different.
solution: in the uploading phase and application set up, we preseve the logs and save it as HAR file
        we parse that, identify the endpoints that possibly retrieves the ID and take them 
"""
def retrieve_id(Har_file,bola_path):
    #print("[!] retrieve_id is called ")
    
    segments=bola_path.split("/")
    index=find_objID(segments)
    
    with open(Har_file,encoding="utf-8") as f:
        har=json.load(f)
    
    entries=har["log"]["entries"]
    for entry in entries:
        har_url=entry["request"]["url"]
        seg_har_url=har_url.split('/')
        if len(seg_har_url) != len(segments):
            continue
        
        if all(b == h for i, (b, h) in enumerate(zip(segments, seg_har_url)) if i != index):
            id=seg_har_url[index]
            if any(c in id for c in ("&", "?", "=")):
                continue
            print(f"\t[!] Id possibly found in {har_url}")
            print(f"\t[?] Id: {id}")
            return id 
        
    return None 


def make_bola_request(account1,account2,bola_url):
    print(f"[!] sending request as user {account1.Label} to endpoint {bola_url} belonging to {account2.Label}")
    headers = {
        "Authorization": f"Bearer {account1.token}",
        "Content-Type": "application/json",
    }
    ans = send_request('GET', url=bola_url, headers=headers)
    return ans
    

    



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