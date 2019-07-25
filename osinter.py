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
from re import findall
from requests import get
from re import search




input_search = input("What do you want to search? ")
ip = get('https://api.ipify.org').text
geolocation = get("https://geo.ipify.org/api/v1?apiKey=&ipAddress=" + ip).text

geolocationip = urllib.request.urlopen("https://geoip-db.com/jsonp/" + input_search)
data = geolocationip.read().decode()
data = data.split("(")[1].strip(")")


print("Please bear in mind that now your Public IP is " + ip + " " + ", located in " + "\n" + data)

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
try:
    raw_response_ip = socket.gethostbyname(input_search)
    raw_response = get('https://censys.io/ipv4/' + raw_response_ip + '/raw').text
    printavel = raw_response.replace('&#34;', '"')
    print(printavel)
except:
    pass

#if "404" in raw_response:
 #   raw_response_ip = socket.gethostbyname(input_search)
  #  raw_responsenew = get('https://censys.io/ipv4/' + raw_response_ip + '/raw').text
   # print(raw_responsenew)
#else:
 #   print(raw_response)
#legit_response = raw_response.replace('&#34;', '"')
#response = legit_response.split('<code class="json">')[1].split('</code>')[0]
#sys.stdout.write(response + '\n')

"""
res = requests.get(API_URL + "/" + str(input_search), auth=(UID, SECRET))
if res.status_code != 200:
    try:
        for name, series in res.json()["raw_series"].iteritems():
            print(series["name"], "was last updated at", series["latest_result"]["timestamp"])
    except:
        pass
"""
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
GET https://api.linkedin.com/v2/{input_search}
"""
print("--------------------------------- FACEBOOK DATA ----------------------------")
token = "EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD"
fb_request_private = requests.get("https://graph.facebook.com/v2.9/search?q=" + input_search + "&type=user&access_token=" + token)
print(fb_request_private)
print("--------- PRINTING DATA FROM FACEBOOK PUBLICALLY ---------------------------")
fb_request_public = requests.get("https://facebook.com/public/" + input_search)
print(fb_request_public.headers)
fb_just_me = requests.get("https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD").text
fb_just_me
try:
    fb_searchbycurl = os.system("C:/Users/Antonio/Desktop/curl/curl.exe -X GET" + " " + "https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=EAAEnQV7kXCcBAEbMc436liLoF3NqqOXQK3faaIZC4lZBtqeTYUoZCvvRQBVibeJ5WjUAWCdhlO36jAD52dOAyN4WvmM1X0jLrR4wXD9WuS6EecJQJajykIOTrzPxLItXgZADUKab4tAHAm5fZAA7BJ321s5mA8dBF5xz9QLIpmZBC2GFGvp4xuvqZAU7LTldxBRNM0yPuOSsQZDZD")
    fb_searchbycurl
except:
    pass

print("-------------------------------------- GITHUB API ---------------------------------")
g = Github("2db60eef1c76f94005cb204b12207958b71fe3ee ")

#for repo in g.get_repos():
 #   print(repo.name)

print("---- REVERSE IP LOOKUP OF YOUR SEARCH")
#print("This one was not properly tested. If nothing shows up, change something....")
lookup = 'https://api.hackertarget.com/reverseiplookup/?q=' + input_search
result = get(lookup).text
print(result)


print("-------------- NAME SERVER LOOKUP -------------------------- ")
#print("This one was not properly tested. If nothing shows up, change something....")
result = get('http://api.hackertarget.com/dnslookup/?q=' + input_search).text
print(result)
print("--------------------------------- LET'S NOW FIND OUT WHICH TECHNOLOGIES WE ARE TALKING ABOUT -----------------------")
#print("This one was not properly tested. If nothing shows up, change something....")
if "https" in input_search:
    input_search.replace("https://", "")
data = get('https://api.wappalyzer.com/lookup-basic/beta/?url=' + input_search).text
jsoned_data = json.loads(data)
technologies = []
print(jsoned_data)
"""
for one in jsoned_data:
        technologies.append(one(int('name')))
for tech in technologies:
        print(tech)
"""

print("----------------- NOW IF THIS FUCKER IS USING A CMS, LET'S FIND OUT ------------------------")
#print("This one was not properly tested. If nothing shows up, change something....")

response = get('https://whatcms.org/?gpreq=json&jsoncallback=jQuery1124008091494457806547_1554361369057&s=%s&na=&nb=1cg805dlm7d7e5eickf67rzxrn12mju6bnch3a99hrt88v7n8rhf0lovwr8d0zm1&verified=&_=1554361369059' + input_search).text
match = search(r'uses<\\/div>[^>]+>(.*?)<\\/a>', response)
print(match)
#print(good + ' ' + match.group(1) + '\n')
#print('Target doesn\'t seem to use a CMS' + '\n')


print("------------------------------ SUBDOMAINS FOUND --------------------------------")
#print("This one was not properly tested. If nothing shows up, change something....")
response = get('https://findsubdomains.com/subdomains-of/' + input_search).text
print(response)
matches = findall(r'(?s)<div class="domains js-domain-name">(.*?)</div>', response)
for match in matches:
    cleanresponse = match.replace(' ', '').replace('\n', '') + '\n'
    print(cleanresponse)

print("------------------- MORE DNS STUFF ----------------------------")
originalrequest = get("https://tools.dnsstuff.com/#dnsReport|type=domain&&value=" + input_search).text
print(originalrequest)

print("--------------- Exploring Google World -------------------------")
#GOOGLE
google = "https://www.google.com/search?filter=0&q=site:" + input_search
getrequrl = "https://www.google.com/search?filter=0&num=100&q=" + input_search + "&start="
req = requests.request(getrequrl)
response = urllib3.requests(req)
data = response.read()
data = re.sub('<b>', '', data)
for e in ('>', '=', '<', '\\', '(', ')', '"', 'http', ':', '//'):
    data = string.replace(data, e, ' ')
    r1 = re.compile('[-_.a-zA-Z0-9.-_]*' + '\.' + ext)
    res = r1.findall(data)
    print(res)

def main(domain):
    list_ext = {"pdf": [], "xls": [], "docx": []}
    for x in list_ext:
        query = "site:%s+filetype:%s" % (domain, x)
        results = googlesearch(query, x)
        list_ext[x] = results
        return list_ext
def output(data, domain=""):
    for key, results in data.iteritems():
        if results:
            results = set(results)
            for x in results:
                x = re.sub('<li class="first">', '', x)
                x = re.sub('</li>', '', x)
                print(x)

print("--------------------- BING IS ALSO COMING TO THE PARTY ----------------------")
print("------------------------- DUCKDUCKGO WILL ALWAYS HAVE ITS PLACE AS WELL -----------------------")


browseropener = input("Do you want to open the browser for the rest of the search engines (11)? (y/n) ")
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
    try:
        puthere = socket.gethostbyname(str(input_search))
        webbrowser.open_new("https://www.onyphe.io/search/?query=" + puthere)
    except:
        pass
    print("----------------------------- RIPE NETWORK COORDINATION CENTER ACTIVITY ---------------------------------")
    webbrowser.open_new("https://stat.ripe.net/" + input_search + "#tabId=activity")
    print("------------------------------ RIPE NETWORK COORDINATION CENTER DNS -------------------------------------")
    webbrowser.open_new("https://stat.ripe.net/" + input_search + "#tabId=dns")
    print("------------------------------- SOCIAL SEARCHER -----------------------------------------")
    webbrowser.open_new("https://www.social-searcher.com/social-buzz/?wblng=&ntw=&psttyp=&searchid=&period=&value=&fbpage=&q5=" + input_search)
    print("----------------------------- CERTIFICATES SEARCH -------------------------------")
    webbrowser.open_new("https://crt.sh/?q=" + input_search)
    print("-------------------- CERTIFICATES TRANSPARENCY BY GOOGLE ----------------------------")
    webbrowser.open_new("https://developers.facebook.com/tools/ct/" + input_search)
    print("---------------------------- CERTIFICATES DB -------------------------------------")
    webbrowser.open_new("https://certdb.com/search/index?q=domain%3A%22" + input_search + "%22")
    print("---------------------------- VIEWDNS-INFO ---------------------------------------------")
    webbrowser.open_new("https://viewdns.info/dnsreport/?domain=" + input_search)
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
certdb.com
developers.facebook.com/tools/ct/
virustotal.com/#/home/search
viewdnsinfo
certificate-transparency.org
google.com/transparencyreport/https/ct
certspotter - tool in python for the same thing about certificates
certdb.com
"https://tools.dnsstuff.com/#dnsReport|type=domain&&value="+str(que))
"""
