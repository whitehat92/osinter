import shodan

api_key="YFJ1LyOqk5KEAvxIiulVBOoPqbVMFHR5"
shodan_api=shodan.Shodan(api_key)

input_search = input("What do you want to search? ")
try:
        # Search Shodan
        results = api.search(input_search)

        # Show the results
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
                print('IP: {}'.format(result['ip_str']))
                print(result['data'])
                print('')
except:
        pass
