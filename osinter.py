import shodan
import sys
import json
import requests
import censys.certificates
#import zoomeye
import robtex_python
import linkedin
import urllib
import webbrowser
import os
from github import Github
import socket
from pybinaryedge import BinaryEdge




input_search = input("What do you want to search? ")

# Search Shodan
api_key = "YFJ1LyOqk5KEAvxIiulVBOoPqbVMFHR5"
shodan_api = shodan.Shodan(api_key)
results = shodan_api.search(input_search)

    # Show the results
print("-------------------------------| SHODAN RESULTS |-------------------------------")
print('Results found: {}'.format(results['total']))
for result in results['matches']:
    print('IP: {}'.format(result['ip_str']))
    print(result['data'])
    print('')

print("--------------------------------- BINARY EDGE SEARCH RESULTS ||||||||| NEED TOKEN FIRST ------------------------------------------")


#be = BinaryEdge(API_KEY)
# Iterate over the first page of IPs having specific ssh configuration
#search = 'ssh.algorithms.encryption.keyword:"aes256-cbc" ssh.banner.keyword:"SSH-2.0-OpenSSH_LeadSec"'
#results = be.host_search(search)
#for ip in results['events']:
 #   print("%s" %(ip['target']['ip']))

    #CENSYS
API_URL = "https://censys.io/api/v1"
UID = "8d439ff9-7b2c-46cc-af3b-350a0077a15f"
SECRET = "ySzM6ohyVtXcFRpcXopbdDGs9S3q3tkJ"

print("--------------------------------| CENSYS RESULTS |--------------------------------------")
res = requests.get(API_URL + "/" + str(input_search), auth=(UID, SECRET))
if res.status_code != 200:
    try:
        for name, series in res.json()["raw_series"].iteritems():
            print(series["name"], "was last updated at", series["latest_result"]["timestamp"])
    except:
        pass

print("----------------------------------| ROBTEX RESULTS |----------------------------------")
print("'''''''''''printing pdns forward results...''''''''''''''''")
response = robtex_python.pdns_forward(input_search)
print(response)
print("''''''''''printing IP of the search'''''''''''")
responseip = robtex_python.ip_query(input_search)
print(responseip)
print("''''''''''printing AS of the search'''''''''''")
responseas = robtex_python.as_query(input_search)
print(responseas)
print("''''''''''printing PDNS REVERSE of the search'''''''''''")
responsepdnsreverse = robtex_python.pdns_reverse(input_search)
print(responsepdnsreverse)



"""
#ZOOMEYE
>>> dir(zoomeye)
['ZoomEye', '__builtins__', '__doc__', '__file__', '__name__', '__package__', 'getpass', 'requests', 'show_ip_port', 'show_site_ip', 'zoomeye_api_test']
>>> zm = zoomeye.ZoomEye()
>>> zm.username = 'username@zoomeye.org'
>>> zm.password = 'password'
>>> print(zm.login())
....JIUzI1NiIsInR5cCI6IkpXVCJ9.....
>>> zm.search('apache country:cn')
>>> data = zm.dork_search('apache country:cn')
>>> zoomeye.show_site_ip(data)
"""


#FULL CONTACT

print("--------------------------------FULL CONTACT------------------------------")

APIkey:"wpSJrr7wVZNEnD6zFjRkUMFo5ijajWRO"

try:
    req = urllib.request.Request('https://api.fullcontact.com/v3/'+input_search, method='post')
    req.add_header('Authorization', 'Bearer wpSJrr7wVZNEnD6zFjRkUMFo5ijajWRO ')
    data = json.dumps([])
    response = urllib.request.urlopen(req)
except:
    pass

print("----------------------------- LINKEDIN DATA ---------------------------------")
"""
LINKEDIN
authentication = linkedin.LinkedInDeveloperAuthentication(CONSUMER_KEY, CONSUMER_SECRET,
                                                          USER_TOKEN, USER_SECRET,
                                                          RETURN_URL, linkedin.PERMISSIONS.enums.values())
# Pass it in to the app...
application = linkedin.LinkedInApplication(authentication)
# Use the app....
application.get_profile()
GET https://api.linkedin.com/v2/{service}
"""
print("--------------------------------- FACEBOOK DATA ----------------------------")
token = "EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD"
fb_request_private = requests.get("https://graph.facebook.com/v2.9/search?q=" + input_search + "&type=user&access_token=" + token)
print(fb_request_private)
fb_request_public = requests.get("https://facebook.com/public/" + input_search)
print(fb_request_public.headers)
fb_just_me = requests.get("https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD").text
fb_just_me
fb_searchbycurl = os.system("C:/Users/Antonio/Desktop/curl/curl.exe -X GET" + " " + "https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD")
fb_searchbycurl

print("-------------------------------------- GITHUB API ---------------------------------")
g = Github("2db60eef1c76f94005cb204b12207958b71fe3ee ")

#for repo in g.get_repos():
 #   print(repo.name)

browseropener = input("Do you want to open the browser for the rest of the search engines (10)? (y/n) ")
if browseropener == "y" or browseropener == "Y" or browseropener == "":
    print("-------------------------- ZOOMEYE opening browser ------------------------------")
    webbrowser.open_new('https://www.zoomeye.org/searchResult?q=' + input_search)
    print(
        "----------------------------------- SYNC ME opening browser! -------------------------------------------")
    webbrowser.open_new('https://sync.me/search/?number=' + input_search)
    print("----------------------------- TALOS INTELLIGENCE -----------------------------")
    webbrowser.open_new("https://talosintelligence.com/reputation_center/lookup?search=" + input_search)
    print("------------------------- PASTEBIN SEARCH -------------------------")
    webbrowser.open_new("https://pastebin.com/search?q=" + input_search)
    print("------------------------------CENSYS SEARCH RESULTS -------------------------------")
    webbrowser.open_new("https://censys.io/ipv4?q=" + input_search)
    print("----------------------------- BGP HURRICANE ELECTRIC INTERNET SERVICES ---------------------------------")
    webbrowser.open_new("https://bgp.he.net/dns/" + input_search + "#_dns")
    print("-------------------------------- PUBLIC FACEBOOK ----------------------------------------")
    webbrowser.open_new("https://facebook.com/public/" + input_search)
    print("------------------------------------- GITHUB SEARCH -------------------------------------")
    webbrowser.open_new("https://github.com/search?q=" + input_search)
    print("-------------------------------------- ONYPHE SEARCH ------------------------------------")
    puthere = socket.gethostbyname(str(input_search))
    webbrowser.open_new("https://www.onyphe.io/search/?query=" + puthere)
    print("----------------------------- RIPE NETWORK COORDINATION CENTER ACTIVITY ---------------------------------")
    webbrowser.open_new("https://stat.ripe.net/" + input_search + "#tabId=activity")
    print("------------------------------ RIPE NETWORK COORDINATION CENTER DNS -------------------------------------")
    webbrowser.open_new("https://stat.ripe.net/" + input_search + "#tabId=dns")


else:
    pass
"""
--- Services
SYNC ME
spokeo
google
bing
pastebin
tello
bgp
arin
viz.graynoise.io/table
fofa.so
onyphe.io
app.binaryedge.io
hunter.io
wigle.net
ghostproject.fr
"""
