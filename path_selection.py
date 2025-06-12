import json
import ipaddress
import geoip2.database

country_trust_map = {}

def ip_belongs(ip_str, network_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(network_str, strict=False)
        return ip in network
    except ValueError as e:
        return False

def get_country(ip, reader):
    # Get the country code for a given IP address using GeoIP2 database.
    try:
        response = reader.country(ip)
        return response.country.iso_code
    except geoip2.errors.GeoIP2Error:
        return 'Unknown'

def get_country_trust(country):
    if country in country_trust_map:
        return country_trust_map[country]
    else:
        if country == 'Unknown':
            country_trust_map[country] = 0.0
        else:
            country_trust_map[country] = 0.2 # Default value (doesn't appear so not very trusted) (may be changed)
        return country_trust_map[country]
    
def are_allies(country1, country2, alliances):
    return any(alliance for alliance in alliances if country1 in alliance['countries'] and country2 in alliance['countries'])

# By default, tor selects about 20 guard nodes, of which 3 are primary.
def guard_security ( client_loc , guards , alliances , reader ) :
# Calculate security score for guard set
# based on client location and adversary model
    client_country = get_country(client_loc, reader)
    scores = {}
    for guard in guards:
        guard_country = guard['country']
        trust_score = get_country_trust(guard_country)
        if client_country == guard_country or are_allies(client_country, guard_country, alliances):
            scores[guard['fingerprint']] = trust_score * 0.5
        else:
            scores[guard['fingerprint']] = trust_score
        
    return scores

def exit_security ( client_loc , dest_loc , guard , exit , alliances ) :
# Score exit relay based on guard / destination
    str = dest_loc.split(':')
    dest_ip = str[0]
    dest_port = None
    if len(str) == 2:
        dest_port = str[1]
    #"reject 0.0.0.0/8:*,

    #check if exit can be used
    exit_policies = exit['exit'].split(', ')
    valid_ports= []
    for policy in exit_policies:
        accept, address = policy.split(' ')
        ip, ports = address.split(':')
        if ports.contains('-'):
            port1,part2 = ports.split('-')
            for port in range(int(port1), int(part2) + 1):
                valid_ports.append(port)
        else:
            valid_ports.append(int(ports))
            
        if accept == 'reject':
            if ip == '*' or dest_ip == ip or ip_belongs(dest_ip, ip):
                if ports == '*' or (dest_port and dest_port in valid_ports):
                    return 0.0
        elif accept == 'accept':
            if ip == '*' or dest_ip == ip or ip_belongs(dest_ip, ip):
                if ports == '*' or (dest_port and dest_port in valid_ports):
                    break
                
    #scoring
        
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

def main():
    reader = geoip2.database.Reader('GeoLite2-Country.mmdb')

    with open('tor_consensus.json', 'r') as file:
        relays = json.load(file)

    for relay in relays:
        relay['country'] = get_country(relay['ip'], reader)

    with open('Project2ClientInput.json', 'r') as file:
        config = json.load(file)

    client_ip = config['Client']
    dest_ip = config['Destination']
    alliances = config['Alliances']

    for alliance in alliances:
        for country in alliance['countries']:
            if country not in country_trust_map:
                country_trust_map[country] = alliance['trust']
            else:
                country_trust_map[country] = min(country_trust_map[country], alliance['trust'])

if __name__ == "__main__":
    main()