from core.models import Account
import os
from core.http_client import send_request
# VERSION: 1 

def authenticate(URL,API,tokenA=None,tokenB=None,tokenAD=None,
                 emailA=None,emailB=None,emailAD=None,
                 usernameA=None,usernameB=None,usernameAD=None,
                 passwordA=None,passwordB=None,passwordAD=None):

    admin_is_provided=None
    print("[!] Authentication started")

    if (tokenAD or (usernameAD and passwordAD)):
        admin_is_provided= True
        print(f"admin is provided:[{ admin_is_provided }] ")

    if (tokenA and tokenB):
        print("mode token")
        AccountA,AccountB = mode_token(tokenA,tokenB)
        return AccountA, AccountB

    elif ((usernameA or emailA) and passwordA) and ((usernameB or emailB) and passwordB):
        # to do next, think of a way to send either the username or email if one available in the first field with the password
        AccountA, AccountB =mode_credentials(URL,API,usernameA,usernameB,passwordA,passwordB)

    return AccountA, AccountB

def mode_token(tokenA,tokenB,tokenAD=None):
    AccountA= Account(
            Label='A',
            token=tokenA)

    AccountB= Account(
            Label='B',
            token=tokenB)
    return AccountA,AccountB

def mode_credentials(URL,API,usernameA,usernameB,passwordA,passwordB):
    print("[!] mode_credentials() is called")
    
    auth_endpoints=[]
    
    with open(os.path.join("wordlists", "auth_endpoints")) as f:
        for line in f:
            auth_endpoints.append(line.strip('\n'))

    
    print("Possible login endpoints:")
    for api in API:
        path = api.path.lower()
        if api.method != 'POST':
            continue
        for kw in auth_endpoints:
            if kw in path:
                api.is_potential_login_endpoint = True
                print(path)
                break

    for api in API:
        
        if api.is_potential_login_endpoint:
            # DOUBLE CHECK 
            path = api.path.lower()
            segments = path.strip('/').split('/')   
            if any(seg in {'login', 'signin', 'sign-in'} for seg in segments):
                print(f'[HIGH] exact login segment: {api.path}')
                login_endpoint=URL+api.path
                
            else:
                print(f'[?]    needs more reasoning: {api.path}')
    
    
    print(f"LOGIN URL: {login_endpoint}") 
    request_response_A= send_request("POST",login_endpoint,json_body={"username": usernameA, "password": passwordA})
    request_response_B= send_request("POST",login_endpoint,json_body={"username": usernameB, "password": passwordB})

    
    
    
    dataA = request_response_A.json() 
    dataB=request_response_B.json()   
    
    for data in dataA:
        if 'token' in data: 
            token_field=data
        
    tokenA = dataA[token_field]    
    print(f"userA: {dataA["message"]}")
    
    tokenB=dataB[token_field]
    print(f"userB: {dataB["message"]}")
    
    print(f"token A: {tokenA} \ntoken B: {tokenB}")
    AccountA= Account(
        Label='A',
        username=usernameA,
        password=passwordA,
        token=tokenA)
    
    AccountB= Account(
            Label='B',
            username=usernameB,
            password=passwordB,
            token=tokenB)
    return AccountA, AccountB
    