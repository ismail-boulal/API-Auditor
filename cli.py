import argparse
from discovery.blackbox import discovery
from parsers import graphql_parser, openapi_parser
import display
from auth.ses import authenticate
from engines.bola import bola
from engines.bfla import bfla
from engines.AccessControlQL import accessControlQL
from report import generate_report
import display
from time import sleep
from core.models import *

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

parser.add_argument("--safe_bola", help="Precise whether you want BOLA to check all endpoints or only safe GET endpoints", action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--loginurl", help="Enter Login Url if available", type=str)


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
# others
findings = []
login_url = args.loginurl
if login_url:
    login_url = url.rstrip('/') + '/' + login_url.lstrip('/')
safe_bola=args.safe_bola
# call the appropiate script
display.banner()
print("[!] Made by: BOULAL Ismail")
print("[!] Supervised by: DATAPROTECT")
print("[!] source code: https://github.com/ismail-boulal/API-Auditor")
print("Press any button to continue...", end="")

input()

if openapi_file:
    API = openapi_parser.parse_openapi(openapi_file)
    display.display_endpoints(API)

elif graphql_schema:
    # ignore that block for the moment we gonna go back to it when we pass to graphql schema
    API = graphql_parser.main(graphql_schema)
else:
    # in case there were only an url given we should try enumerate
    API, login_url = discovery(url, usernameA, emailA, passwordA,login_url)


#exit() # break point 
# # Authenticate
accountA, accountB,accountAD = authenticate(url,API,login_url,tokenA,tokenB,tokenAD,emailA,emailB,emailAD,usernameA,usernameB,usernameAD,passwordA,passwordB,passwordAD)
accounts=[]
for account in (accountA,accountB,accountAD):
    if account:
        accounts.append(account)


# Distinguish rest from graphql
# Distinguish REST from GraphQL

if isinstance(API, GraphQLSchema):
    print("[+] GraphQL API detected")
    # BOLA requires two normal users
    if accountA and accountB:
        findings.extend(accessControlQL(API, accounts, url))

else:
    print("[+] REST API detected")
    # BOLA
    if accountA and accountB:
        findings.extend(bola(endpoints=API,accounts=accounts,url=url,safe_bola=safe_bola))
    # BFLA
    if accountA:
        findings.extend(bfla(endpoints=API,accounts=accounts,url=url))




generate_report(findings)

