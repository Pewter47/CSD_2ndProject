import json
import geoip2.database

def guard_security ( client_loc , guards ) :
# Calculate security score for guard set
# based on client location and adversary model
    return 

def exit_security ( client_loc , dest_loc , guard , exit ) :
# Score exit relay based on guard / destination
    return 

def select_path ( relays , alpha_params ) :
# SUGGESTED_GUARD_PARAMS = {
# ’safe_upper ’: 0.95 ,
# ’safe_lower ’: 2.0 ,
# ’accept_upper ’: 0.5 ,
# ’accept_lower ’: 5.0 ,
# ’ bandwidth_frac ’: 0.2
#}

# SUGGESTED_EXIT_PARAMS = {
# ’safe_upper ’: 0.95 ,
# ’safe_lower ’: 2.0 ,
# ’accept_upper ’: 0.1 ,
# ’accept_lower ’: 10.0 ,
# ’ bandwidth_frac ’: 0.2
#}
# Sort relays by descending trust score
# Separate into safe / acceptable categories ( recommended values above )
# Select until Bandwidth threshold reached .
# Return bandwidth - weighted choice .
    return

country_trust_map = {}

def get_country_trust(country):
    if country in country_trust_map:
        return country_trust_map[country]
    else:
        country_trust_map[country] = 0.5
        return country_trust_map[country]

def main():
    reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

    with open('tor_consensus.json', 'r') as file:
        relays = json.load(file)

    for relay in relays:
        try:
            response = reader.country(relay['ip'])
            relay['country'] = response.country.iso_code
        except geoip2.errors.GeoIP2Error:
            relay['country'] = 'Unknown'

    with open('Project2ClientInput.json', 'r') as file:
        config = json.load(file)

    client_ip = config['Client']
    dest_ip = config['Destination']

    for alliance in config['Alliances']:
        for country in alliance['countries']:
            if country not in country_trust_map:
                country_trust_map[country] = alliance['trust']
            else:
                country_trust_map[country] = min(country_trust_map[country], alliance['trust'])

    print(country_trust_map)

if __name__ == "__main__":
    main()