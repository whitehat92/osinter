import shodan
import sys
import json
import requests
import censys.certificates
import zoomeye
import robtex_python
import linkedin



api_key = "YFJ1LyOqk5KEAvxIiulVBOoPqbVMFHR5"
shodan_api = shodan.Shodan(api_key)

input_search = input("What do you want to search? ")

# Search Shodan
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
res = requests.get(API_URL + "/" + str(input_search), auth=(UID, SECRET))
if res.status_code != 200:
    try:
        print("error occurred: %s" % res.json()["error"])
        sys.exit(1)
        for name, series in res.json()["raw_series"].iteritems():
            print(series["name"], "was last updated at", series["latest_result"]["timestamp"])
    except:
        pass

    #----CERTIFICATES----
"""
UID = "8d439ff9-7b2c-46cc-af3b-350a0077a15f"
SECRET = "ySzM6ohyVtXcFRpcXopbdDGs9S3q3tkJ"

certificates = censys.certificates.CensysCertificates(UID, SECRET)
fields = ["parsed.subject_dn", "parsed.fingerprint_sha256", "parsed.fingerprint_sha1"]

for c in certificates.search("validation.nss.valid: true", fields=fields):
    print(c["parsed.subject_dn"])
"""

print("----------------------------------| ROBTEX RESULTS |----------------------------------")
print("'''''''''''printing pdns forward results...''''''''''''''''")
response = robtex_python.pdns_forward(input_search)
print("''''''''''printing IP of the search'''''''''''")
responseip = robtex_python.ip_query(input_search)
print("''''''''''printing AS of the search'''''''''''")
responseas = robtex_python.as_query(input_search)
print("''''''''''printing PDNS REVERSE of the search'''''''''''")
responsepdnsreverse = robtex_python.pdns_reverse(input_search)



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

"""
FULL CONTACT

APIkey: wpSJrr7wVZNEnD6zFjRkUMFo5ijajWRO


req = urllib.request.Request('https://api.fullcontact.com/v3/<search>')
req.add_header('Authorization', 'Bearer {wpSJrr7wVZNEnD6zFjRkUMFo5ijajWRO}')
data = json.dumps({
  "emails": [
    "bart@fullcontact.com",
    "bart.lorang@fullcontact.com"
  ],
  "phones": [
    "+17202227799",
    "+13035551234"
  ],
  "location": {
    "addressLine1": "123 Main Street",
    "addressLine2": "Unit 2",
    "city": "Denver",
    "region": "Colorado",
    "regionCode": "CO",
    "postalCode": "80203"
  },
  "name": {
    "full": "Bart Lorang",
    "given": "Bart",
    "family": "Lorang"
  },
  "profiles": [{
    "service": "twitter",
    "username": "bartlorang"
    }, {
    "service": "twitter",
    "userid": "5998422"
    }, {
    "service": "linkedin",
    "url": "https://www.linkedin.com/in/bartlorang"
    }, {
    "service": "github",
    "url": "https://www.github.com/lorangb"
  }]
})

response = urllib.request.urlopen(req,data)

"""

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
