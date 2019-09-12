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
from random import randint
from re import findall
from requests import get
from re import search
import urllib.request
import csv
from pylatex import Document, Section, Math, Tabular, Figure, SubFigure, \
    Package, TikZ, Axis, Plot, Itemize, Enumerate, Description, MultiColumn, \
    MultiRow, Command, Matrix, VectorName, Quantity, TableRowSizeError, \
    LongTable, FlushLeft, FlushRight, Center, MiniPage, TextBlock, \
    PageStyle, Head, Foot, StandAloneGraphic, Tabularx, ColumnType, NewLine, \
    LineBreak, NewPage, HFill, HugeText, LargeText, MediumText, \
    SmallText, FootnoteText, TextColor, FBox, MdFramed, Tabu, \
    HorizontalSpace, VerticalSpace, NoEscape, Table, LongTabu, Subsection
from pylatex.utils import escape_latex, fix_filename, dumps_list, bold, \
    italic, verbatim
import googlesearch
import bs4
import selenium.webdriver as webdriver



input_search = input("What do you want to search? ")
ip = get('https://api.ipify.org').text
geolocation = get("https://geo.ipify.org/api/v1?apiKey=&ipAddre     ss=" + ip).text

geolocationip = urllib.request.urlopen("https://geoip-db.com/jsonp/" + input_search)
data = geolocationip.read().decode()
data = data.split("(")[1].strip(")")


print("Please bear in mind that now your Public IP is " + ip + " " + ", located in " + "\n" + data)

# Search Shodan
api_key = "KEY"
shodan_api = shodan.Shodan(api_key)
results = shodan_api.search(input_search)
# Show the results
print("-------------------------------| SHODAN RESULTS |-------------------------------")
print('Results found: {}'.format(results['total']))
shody = results['matches']
for resultshodan in shody:
    print('IP: {}'.format(resultshodan['ip_str']))
    print(resultshodan['data'])
    print('')


    #CENSYS
API_URL = "https://censys.io/api/v1"
UID = "8d439ff9-7b2c-46cc-af3b-350a0077a15f"
SECRET = "KEY"

print("--------------------------------| CENSYS RESULTS |--------------------------------------")
try:
    raw_response_ip = socket.gethostbyname(input_search)
    raw_response = get('https://censys.io/ipv4/' + raw_response_ip + '/raw').text
    censys_clean = raw_response.replace('&#34;', '"')
    #print(censys_clean)
    print(censys_clean)
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
pdns_forward = robtex_python.pdns_forward(input_search)
print(pdns_forward)
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
#my access token: KEY"
#['ZoomEye', '__builtins__', '__doc__', '__file__', '__name__', '__package__', 'getpass', 'requests', 'show_ip_port', 'show_site_ip', 'zoomeye_api_test']
#zm = zoomeye.ZoomEye()
#print(zm)
#zm.login()
#zm.dork_search(input_search)
#zm.search('apache country:cn')
#data = zm.dork_search('apache country:cn')


#FULL CONTACT

print("--------------------------------FULL CONTACT------------------------------")

APIkey:"KEY"

try:
    req = urllib.request.Request('https://api.fullcontact.com/v3/'+input_search, method='post')
    req.add_header('Authorization', 'Bearer KEY ')
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
token = "KEY"
fb_request_private = requests.get("https://graph.facebook.com/v2.9/search?q=" + input_search + "&type=user&access_token=" + token)
print(fb_request_private)
print("--------- PRINTING DATA FROM FACEBOOK PUBLICALLY ---------------------------")
fb_request_public = requests.get("https://facebook.com/public/" + input_search)
print(fb_request_public.headers)
fb_just_me = requests.get("https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=KEY").text
fb_just_me
try:
    fb_searchbycurl = os.system("C:/pathtocurl -X GET" + " " + "https://graph.facebook.com/v3.3/me?fields=id%2Cname%2Cphotos&access_token=KEY")
    fb_searchbycurl
except:
    pass

print("-------------------------------------- GITHUB API ---------------------------------")
g = Github("KEY ")

#for repo in g.get_repos():
 #   print(repo.name)

print("---- REVERSE IP LOOKUP OF YOUR SEARCH")
#print("This one was not properly tested. If nothing shows up, change something....")
lookup = 'https://api.hackertarget.com/reverseiplookup/?q=' + input_search
resultlookup = get(lookup).text
print(resultlookup)


print("-------------- NAME SERVER LOOKUP -------------------------- ")
#print("This one was not properly tested. If nothing shows up, change something....")
resultnameserver = get('http://api.hackertarget.com/dnslookup/?q=' + input_search).text
print(resultnameserver)
print("--------------------------------- LET'S NOW FIND OUT WHICH TECHNOLOGIES WE ARE TALKING ABOUT -----------------------")
#print("This one was not properly tested. If nothing shows up, change something....")
if "https" in input_search:
    input_search.replace("https://", "")
data = get('https://api.larger.io/v1/search/key/KEY?domain=' + input_search).text
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

response = get('https://whatcms.org/?gpreq=json&jsoncallback=jQueryKEY&s=%s&na=&nb=KEY&verified=&_=KEY' + input_search).text
match = search(r'uses<\\/div>[^>]+>(.*?)<\\/a>', response)
print(match)
#print(good + ' ' + match.group(1) + '\n')
#print('Target doesn\'t seem to use a CMS' + '\n')


print("------------------------------ SUBDOMAINS FOUND --------------------------------")
#print("This one was not properly tested. If nothing shows up, change something....")
subdomains = get('https://findsubdomains.com/subdomains-of/' + input_search).text
print(subdomains)

"""
matches = findall(r'(?s)<div class="domains js-domain-name">(.*?)</div>', response)
for match in matches:
    cleanresponse = match.replace(' ', '').replace('\n', '') + '\n'
    print(cleanresponse)
"""

print("VIRUSTOTAL")
vt = urllib.request.urlopen("https://www.virustotal.com/gui/domain/" + input_search + "/relations")
vtjson = vt.read().decode()
print(vtjson)

print("--------------- Exploring Google World -------------------------")
query = input_search
try:
    searchgoogle = googlesearch.search(query, tld='com', lang='en', tbs='0', safe='off', num=10, start=0, stop=None, domains=None, pause=4.0, only_standard=False, extra_params={}, tpe='', user_agent="Mozilla/10.0")
    for item in searchgoogle:
        print(item)
except:
    pass
"""
HOW TO WORK WITH GOOGLE SEARCH: vv
query (str) – Query string. Must NOT be url-encoded.
tld (str) – Top level domain.
lang (str) – Language.
tbs (str) – Time limits (i.e “qdr:h” => last hour, “qdr:d” => last 24 hours, “qdr:m” => last month).
safe (str) – Safe search.
num (int) – Number of results per page.
start (int) – First result to retrieve.
or None stop (int) – Last result to retrieve. Use None to keep searching forever.
of str or None domains (list) – A list of web domains to constrain the search.
pause (float) – Lapse to wait between HTTP requests. A lapse too long will make the search slow, but a lapse too short may cause Google to block your IP. Your mileage may vary!
only_standard (bool) – If True, only returns the standard results from each page. If False, it returns every possible link from each page, except for those that point back to Google itself. Defaults to False for backwards compatibility with older versions of this module.
of str to str extra_params (dict) – A dictionary of extra HTTP GET parameters, which must be URL encoded. For example if you don’t want Google to filter similar results you can set the extra_params to {‘filter’: ‘0’} which will append ‘&filter=0’ to every query.
tpe (str) – Search type (images, videos, news, shopping, books, apps) Use the following values {videos: ‘vid’, images: ‘isch’, news: ‘nws’, shopping: ‘shop’, books: ‘bks’, applications: ‘app’}
or None user_agent (str) – User agent for the HTTP requests. Use None for the default.
"""
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
    webbrowser.open_new("https://www.bing.com/search?q=" + input_search + "&qs=n&form=QBLH&sp=-1&pq=" + input_search + ".co&sc=0-18&sk=&cvid=KEY")
    print("------------------------- DUCKDUCKGO  -----------------------")
    webbrowser.open_new("https://duckduckgo.com/?q=" + input_search + "&t=h_&ia=web")
    print("--------------------- GOOGLE ----------------------")
    webbrowser.open_new("https://www.google.com/search?ei=KEY" + input_search + "&oq=" + input_search + "&gs_l=KEY&ved=KEY&uact=5")
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
    if __name__ == '__main__':
        doc = Document()
        doc.preamble.append(Command('title', input_search))
        doc.preamble.append(Command('author', 'YOURNAME'))
        doc.preamble.append(Command('date', NoEscape(r'\today')))
        doc.append(NoEscape(r'\maketitle'))
        with doc.create(Section('Searching')):
            doc.append('Analyzis of ' + " " + input_search)
        with doc.create(Section('Name server lookup')):
            doc.append(resultnameserver)
        with doc.create(Section("Reverse IP lookup")):
            doc.append(resultlookup)
            #doc.append(italic('italic text. '))
        with doc.create(Section('Subdomains')):
            doc.append('Analyzis of ' + " " + subdomains)
        with doc.create(Section("Technologies")):
            doc.append(jsoned_data)
        with doc.create(Section("Censys")):
            #doc.append(censys_clean)
            doc.append(censys_clean)
        with doc.create(Section("VIRUSTOTAL")):
            doc.append(vtjson)
        with doc.create(Section("What's said on Google")):
            doc.append(searchgoogle)
            #with doc.create(Subsection('A subsection')):
             #   doc.append('Also some crazy characters: $&#{}')
        # Document with `\maketitle` command activated
        doc.append(NewPage)
        with doc.create(Section("Table1")):
            with doc.create(Tabular(table_spec='|l|l|')) as table1:
                table1.add_hline()
                table1.add_row("Name Server Lookup", MultiColumn(1, align=NoEscape(r'p{11cm}|'), data=resultnameserver))
                table1.add_hline()
                table1.add_row("Robtex", MultiColumn(1, align=NoEscape(r'p{16cm}|'), data=pdns_forward))
                table1.add_hline()
                table1.add_row("Robtex1", MultiColumn(1, align=NoEscape(r'p{16cm}|'), data=responseip))
                table1.add_hline()
                table1.add_row("Robtex2", MultiColumn(1, align=NoEscape(r'p{16cm}|'), data=responseas))
                table1.add_hline()
                table1.add_row("Tech", MultiColumn(1, align=NoEscape(r'p{16cm}|'), data=jsoned_data))
                table1.add_hline()
        doc.generate_pdf('osinter', clean_tex=False)

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
europeliveuamap.com - spatial database
https://nuclearsecrecy.com/nukemap/
https://www.n2yo.com/
https://wifispc.com/
freekeywordresearch.com
keyworddiscovery.com
https://www.bincodes.com/bin-search/ --> Bins
pic2map.com
https://www.pic2map.com/
https://wigle.net/
archive.is
waybackmachine
https://www.boatinfoworld.com/
http://www.internationalcrimesdatabase.org/
vat-lookup.co.uk
https://bitcoinwhoswho.com/
https://www.dgmarket.com/ --> work
https://www.commercial-register.sg.ch/ --> registrars
https://pt.kompass.com/ 
https://knowem.com/ --> people search
start.me
https://start.me/p/VRxaj5/dating-apps-and-hook-up-sites-for-investigators --> dating
http://irc.netsplit.de/channels/ --> IRC
http://searchlr.net/ --> tumblr search engine
resavr.com --> REDDIT deleted
https://codeofaninja.com/tools/find-instagram-user-id --> instagram, for ID
http://www.geocreepy.com/
https://iotscanner.bullguard.com/
https://millionshort.com/ --> google last page
similarsites.com
https://www.searchftps.net/
etools.ch --> metasearch
"""


#error handling
#Exception, <variablename_toexpress the error:
#print(str(variablename_toexpress the error)


#Latex code
"""
if __name__ == '__main__':
    doc = Document()
with doc.create(Section("Table2")):
    with doc.create(Tabular(table_spec='|c|l|')) as table2:
        table2.add_hline
        # table2.add_row("Vuln", MultiColumn(1, align=NoEscape(r'p{11.5cm}|'), data=x))
        table2.add_row("Description", MultiColumn(1, align=NoEscape(r'p{11.5cm}|'), data=variable))
        table2.add_hline()
        table2.add_row("CVE", MultiColumn(1, align=NoEscape(r'p{11.5cm}|'), data=item))
        table2.add_hline()
        table2.add_row("Medium", MultiColumn(1, align=NoEscape(r'p{11.5cm}|'), data=y))
        table2.add_hline()
doc.generate_pdf('osinter', clean_tex=False)
"""
