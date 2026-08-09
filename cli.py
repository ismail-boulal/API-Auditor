import argparse
from discovery import blackbox
from parsers import graphql_parser, openapi_parser
import display
from auth.ses import authenticate
from engines.bola import bola
from engines.bfla import bfla

# Version : 1
# This File has as an objective the arguments taking from the user that should be 
#     - openapi specification
#     - graphql schema
#     - general url 
#     - Users Token 
#     - Possibly Users credentials 


parser = argparse.ArgumentParser()

# Step 1: identify inputs
parser.add_argument("--url", help="API url", type=str, required=True)
parser.add_argument("--openapi", help="Path to OpenAPI specification", type=str)
parser.add_argument("--graphql", help="Path to GraphQL schema", type=str)

parser.add_argument("--tokenA", help="Authentication Token for User A", type=str)
parser.add_argument("--tokenB", help="Authentication Token for User B", type=str)
parser.add_argument("--tokenAD", help="Authentication Token for administrator if available", type=str)

parser.add_argument("--emailA", help="Enter email for User A", type=str)
parser.add_argument("--emailB", help="Enter email for User A", type=str)
parser.add_argument("--emailAD", help="Enter email for Admin if available", type=str)

parser.add_argument("--usernameA", help="Enter usernames for User A", type=str)
parser.add_argument("--usernameB", help="Enter usernames for User B", type=str)
parser.add_argument("--usernameAD", help="Enter usernames for Admin if available", type=str)


parser.add_argument("--passwordA", help="Enter Password for User A", type=str)
parser.add_argument("--passwordB", help="Enter Password for User A", type=str)
parser.add_argument("--passwordAD", help="Enter Password for Admin if available", type=str)



args = parser.parse_args()

# handle Input issues
# if (args.tokenA and args.tokenB) is None and ((args.usernameA and args.usernameB) is None or (args.passwordA and args.passwordB) is None):
#      parser.error("Please provide either --tokens or both --usernames and --passwords")

# declare variables
# base url
url = args.url
# tokens
tokenA = args.tokenA
tokenB = args.tokenB
tokenAD = args.tokenAD
# emails
emailA = args.emailA
emailB = args.emailB
emailAD = args.emailAD
# usernames
usernameA = args.usernameA
usernameB = args.usernameB
usernameAD = args.usernameAD
# passwords 
passwordA = args.passwordA
passwordB = args.passwordB
passwordAD = args.passwordAD
# documentation if provided. 
openapi_file = args.openapi
graphql_schema = args.graphql

# call the appropiate script 
if openapi_file:
    API=openapi_parser.parse_openapi(openapi_file)
    display.display_endpoints(API)
if graphql_schema:
    graphql_parser.main()
elif openapi_file is None and graphql_schema is None:
    blackbox.main()

#TESTING DEBUGGING
# from TESTER import tester
# tester(API)
# exit()
# Authenticate
accountA, accountB,accountAD = authenticate(url,API,tokenA,tokenB,tokenAD,emailA,emailB,emailAD,usernameA,usernameB,usernameAD,passwordA,passwordB,passwordAD)
accounts=[]
for account in (accountA,accountB,accountAD):
    if account:
        accounts.append(account)
        
findings=[]        
# BOLA ENGINE (DISABLED FOR THE MOMENT)
if accountA and accountB:
    findings.append(bola(endpoints=API,accounts=accounts,url=url))
# BFLA ENGINE
if accountA:
    pass
    findings.append(bfla(endpoints=API,accounts=accounts,url=url))

