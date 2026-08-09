# # This function is for each endpoint in endpoints and depends if we passed account A or B 
# def make_normal_request(account,bola_url,base_url):
    
#     if account.Label == 'A':
#         id='7' # hardcoded for the moment, until future improvements 
#     else:
#         id='8'
        
#     url=base_url+bola_url.path
#     url=find_substitute_objID(account,url)
    
#     print(f"sending request as user {account.Label}")
#     ans=send_request('GET',url=url,json_body=f'Authorization: Bearer {account.token}')
#     print(ans.json())

#     return ans

# --------------------------------------------------------------------------------------------- 

        # if body_is_required:
        #     schema=endpoint.request_body.schema
        #     properties= schema['application/json']['schema']['properties']
        #     print(f"{endpoint.path} requires:")
        #     request_body={}
        #     for prop in properties:
        #         type=properties[prop]['type']
        #         print(f"\tproperty: {prop}\n\ttype: {type}")
        

 # --------------------------------------------------------------------------------------------- 
   
    # for account in accounts:
    #     role=account.role
    #     if role is None:
    #         try:
    #             headers = {
    #                 "Authorization": f"Bearer {account.token}",
    #                 "Content-Type": "application/json",
    #             }
    #             ans=send_request('GET', url="http://192.168.1.1:8091/profile", headers=headers) # we gonna cheat for the moment 
    #             response_data=ans.json()
    #             role=extract_field(response_data, ROLE_FIELDS)
    #         except Exception as e:
    #             print(f"error {e}")
    #     print(f"[+] ROLE of User{account.Label}: {role}")
    
# --------------------------------------------------------------------------------------------- 
    # schema = endpoint.request_body.schema
    # for _, media in schema.items():
    #     body_schema = media.get('schema', {})
    #     properties = body_schema.get('properties', {})
    #     if not properties:
    #         continue
    #     print(f"{endpoint.path} requires:")
    #     for prop, definition in properties.items():
    #         type=definition.get('type')
    #         print(f"\tproperty: {prop}\n\ttype: {type}")
    #         if type == "string":
    #             request_body[prop]="random"
    #         elif type == 'integer' or type == 'number':
    #             request_body[prop]=random.randint(1,200)
    #         elif type == 'array':
    #             request_body[prop] = ['random','random']
# --------------------------------------------------------------------------------------------- 
# methodology:
#     we should start as same as BOLA, endpoints and accounts objects
#     the vulnerability this time isn't about lateral authorization but vertical authorization
#     meaning we have two choices:
#         - start with normal account and admin account
#         - work only with normal account if no admin is provided
#     the essential is that using a normal account you get to interact with an endpoint that requires (normally) a higher role
#     so the script must take each endpoint in endpoints:
#         - see the endpoint.method and prioritize DELETE, PUT, PATCH, POST, GET
#         - take the endpoint.path  and see if the words ring a bell
#         - see through metadata like operation_id, summary, descripton, tags, response
#     after collecting a list of informations of BFLA candidate, loop through each candidate and:
#         - there is many BFLA cases in candidate:
#             - an endpoint highly administrative like POST /admin/users (to be called from a lower privileger user)
#             - endpoints with actions that seem sensitive like PUT /users/v1/{username}/password or role modification
#         - a baseline? if admin is provided check to see if he can do it correctly then initialize the request from a normal role
#         - after executing BFLA check the response body and look for keywords indicating that it's successful;
#         maybe even try GETting that resource again (in case it was deleted or modified) and comfirm it was indeed changed from a normal user POV
#             DELETE   -> verifier que la ressource n'existe plus
#             PATCH    -> recuperer la ressource et comparer le champ
#             POST     -> verifier que la ressource a ete creee
#             APPROVE  -> verifier que status == approved
#         - add that into Findings
#     N.B: sometimes APIs rely role field, sometimes they only use the path, sometimes its the method

#     1. Detection des endpoints sensibles
#     2. Generation automatique des parametres
#     3. Generation automatique des bodies
#     4. Collecte des identifiants depuis les reponses
#     5. Analyse et verification des effets


# --------------------------------------------------------------------------------------------- 
    # properties=(BFLA_endpoint.request_body and BFLA_endpoint.request_body.properties) or {}
    # bfla_properties=[property for property in properties if property]