import shodan
import sys
import json
import requests
import censys.certificates

api_key = "YFJ1LyOqk5KEAvxIiulVBOoPqbVMFHR5"
shodan_api = shodan.Shodan(api_key)

input_search = input("What do you want to search? ")

# Search Shodan
results = shodan_api.search(input_search)

    # Show the results
print('Results found: {}'.format(results['total']))
for result in results['matches']:
    print('IP: {}'.format(result['ip_str']))
    print(result['data'])
    print('')



    #CENSYS
"""
import sys
import json
import requests

API_URL = "https://censys.io/api/v1"
UID = "8d439ff9-7b2c-46cc-af3b-350a0077a15f"
SECRET = "ySzM6ohyVtXcFRpcXopbdDGs9S3q3tkJ"

res = requests.get(API_URL + "/data", auth=(UID, SECRET))
if res.status_code != 200:
    print "error occurred: %s" % res.json()["error"]
    sys.exit(1)
for name, series in res.json()["raw_series"].iteritems():
    print series["name"], "was last updated at", series["latest_result"]["timestamp"]

    ----CERTIFICATES----

import censys.certificates

UID = "8d439ff9-7b2c-46cc-af3b-350a0077a15f"
SECRET = "ySzM6ohyVtXcFRpcXopbdDGs9S3q3tkJ"

certificates = censys.certificates.CensysCertificates(UID, SECRET)
fields = ["parsed.subject_dn", "parsed.fingerprint_sha256", "parsed.fingerprint_sha1"]

for c in certificates.search("validation.nss.valid: true", fields=fields):
    print c["parsed.subject_dn"]

"""
