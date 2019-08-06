import shodan
import sys
import json
import requests
import censys.certificates
import zoomeye
import robtex_python
import linkedin
import urllib
import webbrowser
import os
from github import Github
import socket
from re import findall
from requests import get
from re import search
import urllib.request



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
print("printing pdns (PowerDNS |-| A CACHING DNS PROXY SERVER) forward results...")
response = robtex_python.pdns_forward(input_search)
print(response)
print("''''''''''printing IP of the search'''''''''''")
responseip = robtex_python.ip_query(input_search)
print(responseip)
print("''''''''''printing the Autonomous System (routable network within Public Internet) of the search'''''''''''")
responseas = robtex_python.as_query(input_search)
print(responseas)
print("''''''''''printing REVERSE PDNS of the search'''''''''''")
responsepdnsreverse = robtex_python.pdns_reverse(input_search)
print(responsepdnsreverse)



print("ZOOMEYE RESULTS")
#ZOOMEYE
#my access token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6InplX2NvcnJlaWE5M0Bob3RtYWlsLmNvbSIsImlhdCI6MTU2NDI1MzU0MywibmJmIjoxNTY0MjUzNTQzLCJleHAiOjE1NjQyOTY3NDN9.Ghw8moQfhR0qzMMv4U8-prGrOImQ6i7vjtUkqzh_r28"
#['ZoomEye', '__builtins__', '__doc__', '__file__', '__name__', '__package__', 'getpass', 'requests', 'show_ip_port', 'show_site_ip', 'zoomeye_api_test']
#zm = zoomeye.ZoomEye()
#print(zm)
#zm.login()
#zm.dork_search(input_search)
#zm.search('apache country:cn')
#data = zm.dork_search('apache country:cn')


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

"""
matches = findall(r'(?s)<div class="domains js-domain-name">(.*?)</div>', response)
for match in matches:
    cleanresponse = match.replace(' ', '').replace('\n', '') + '\n'
    print(cleanresponse)
"""

print("--------------- Exploring Google World ------------------------- still trying")
#GOOGLE
try:
    req = urllib.request.Request("https://www.google.com/search?ei=kho6XZakEY2xULj4uvAE&q=" + input_search + "&oq=" + input_search + "&gs_l=psy-ab.3...24584.26899..27013...0.0..0.0.0.......0....1..gws-wiz.....0..0i71.99Zu33H4yCI&ved=0ahUKEwiWtcq__dDjAhWNGBQKHTi8Dk4Q4dUDCAo&uact=5")
    print(req)
except:
    pass

google_dorks = input("Do you want to use Google dorks? ")
if google_dorks == "" or google_dorks == "y" or google_dorks == "Y":
    printlist = input("Do you know which parameters are available? ")
    if printlist == "y" or printlist == "Y" or printlist == "":
        yesdorks = input("Please specify your query: ")
    else:
        print("Here are the basic parameters:")
        print("allintext: searches for specific text contained on any web page")
        print("allinurl: it can be used to fetch results whose URL contains all the specified characters")
        print("allintitle: exactly the same as allintext, but will show pages that contain titles with X characters")
        print("filetype")
        print("intitle: used to search for various keywords inside the title")
        print("intext: useful to locate pages that contain certain characters or strings inside their text")
        print("ext: type of extension who you want to include in your search")
    definitivedorks = input("So.. build now your query: ")
    webbrowser.open_new("https://www.google.com/search?q=" + definitivedorks)



browseropener = input("Do you want to open the browser for the rest of the search engines (25)? (y/n) ")
if browseropener == "y" or browseropener == "Y" or browseropener == "":
    print("--------------------- BING  ----------------------")
    webbrowser.open_new("https://www.bing.com/search?q=antonio-correia.com&qs=n&form=QBLH&sp=-1&pq=" + input_search + ".co&sc=0-18&sk=&cvid=855BB34029354D538EC5F30BF05675CA")
    print("------------------------- DUCKDUCKGO  -----------------------")
    webbrowser.open_new("https://duckduckgo.com/?q=" + input_search + "&t=h_&ia=web")
    print("--------------------- GOOGLE ----------------------")
    webbrowser.open_new("https://www.google.com/search?ei=kho6XZakEY2xULj4uvAE&q=" + input_search + "&oq=" + input_search + "&gs_l=psy-ab.3...24584.26899..27013...0.0..0.0.0.......0....1..gws-wiz.....0..0i71.99Zu33H4yCI&ved=0ahUKEwiWtcq__dDjAhWNGBQKHTi8Dk4Q4dUDCAo&uact=5")
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
    print("----------------------------------- DNS STUFF TOOLS -------------------------------")
    webbrowser.open_new("https://tools.dnsstuff.com/#dnsReport|type=domain&&value=" + input_search)
    print("------------------ WAYBACK MACHINE -------------------------------------")
    webbrowser.open_new("https://web.archive.org/details/" + input_search)
    print("--------------------- IPV4INFO ----------------------------")
    webbrowser.open_new("https://" + input_search + "websiteoutlook.com/")
    print("------------------------- CERTSPOTTER ---------------------------------")
    webbrowser.open_new("https://certspotter.com/api/v0/certs\?domain\=" + input_search)
    print("------------------------ CRTSH -------------------------------------------")
    webbrowser.open_new("https://certspotter.com/api/v0/certs\?domain\=" + input_search)

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
asnlookup to look for ip zones. A company always has a set of IP's assigned. in order to look for the zones associated with those
IP's, one should look for the ASN to find out exactly to which location or zone that IP belongs to.

databreaches.net
https://www.searchencrypt.com/
europeliveuamap.com - base de dados espacial. entrar por liveuamap.com e escolher o país, senao somos barrados pela membership
https://nuclearsecrecy.com/nukemap/
https://www.n2yo.com/
https://wifispc.com/
freekeywordresearch.com
keyworddiscovery.com
https://www.bincodes.com/bin-search/ --> procurar os bins ou identificadores bancários
pic2map.com
https://www.pic2map.com/
https://wigle.net/
archive.is
waybackmachine
https://www.boatinfoworld.com/
http://www.internationalcrimesdatabase.org/
vat-lookup.co.uk
https://bitcoinwhoswho.com/
https://www.dgmarket.com/ --> concursos públicos, em portugal é o portalbase
https://www.commercial-register.sg.ch/ --> registars das empresas
https://pt.kompass.com/ 
https://knowem.com/ --> procurar pessoas, pipl.com também
start.me
https://start.me/p/VRxaj5/dating-apps-and-hook-up-sites-for-investigators --> agregador de várias redes de dating
http://irc.netsplit.de/channels/ --> procurar no irc pelo tema desejado
http://searchlr.net/ --> tumblr search engine
resavr.com --> reddit search, coisas que foram apagadas
https://codeofaninja.com/tools/find-instagram-user-id --> procurar pelo id do user
http://www.geocreepy.com/
https://iotscanner.bullguard.com/
https://millionshort.com/ --> procurar resultados que estão na 15ªa página
similarsites.com
https://www.searchftps.net/
etools.ch --> metasearc
"""


#error handling
#Exception, <variablename_toexpress the error:
#print(str(variablename_toexpress the error)
