import json
import ipaddress
import geoip2.database

# Structure : {country:[ c1: {'c2': s2, 'c3': s3}, c2: {'c1': s1, 'c3': s3}, ...], c2: {...}, ...}
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

def get_alliance_trust(country1, country2, alliances):
    if country1 == country2:
        return 0.0
    for alliance in alliances:
        if country1 in alliance['countries'] and country2 in alliance['countries']:
            return alliance['trust']
    return 1.0

# By default, tor selects about 20 guard nodes, of which 3 are primary.
def guard_security ( client_loc , guards , alliances, reader ) :
    # Calculate security score for guard set
    # based on client location and adversary model
    client_country = get_country(client_loc, reader)
    scores = []
    for guard in guards:
        guard_country = guard['country']
        trust_score = get_country_trust(guard_country) * get_alliance_trust(client_country, guard_country, alliances)
        if trust_score > 0:
            scores.append((guard, trust_score))

    top10_guards =  sorted(scores, key=lambda x: x[1], reverse=True)[:10]  # Select top 10 guards
    # Sort guards by descending trust score and select top 10

    return top10_guards

def exit_security ( client_loc , dest_loc , guard , exit , alliances , reader) :
    # Score exit relay based on guard / destination
    # check a pair of exit and guard relays

    # Anti AS 
    if(guard['fingerprint'] == exit['fingerprint'] or ('family' in guard and exit['fingerprint'] in guard['family'])):
        return 0.0
    parts = dest_loc.split(':')
    dest_ip = parts[0]
    dest_port = int(parts[1]) if len(parts) == 2 else None

    exit_policies = exit['exit'].split(',')
    for policy in exit_policies:
        rule, address = policy.strip().split(' ')
        ip, ports = address.split(':')

        if ports == '*':
            portmin, portmax = 0, 65535
        elif '-' in ports:
            portmin, portmax = map(int, ports.split('-'))
        else:
            portmin = portmax = int(ports)

        ip_match = (ip == '*') or (dest_ip == ip) or ip_belongs(dest_ip, ip)
        port_match = dest_port is None or (portmin <= dest_port <= portmax)

        if rule == 'reject' and ip_match and port_match:
            return 0.0 # Assume exits always have reject *:*
        elif rule == 'accept' and ip_match and port_match:
            break # If we find an accept rule, we can proceed

    #scoring
    guard_country = guard["country"]
    exit_country = exit["country"]
    client_country = get_country(client_loc, reader)
    dest_country = get_country(dest_loc, reader)

    base_score = min(get_country_trust(exit_country), get_country_trust(guard_country))
    
    client_exit_penalty = get_alliance_trust(client_country, exit_country, alliances)
    guard_dest_penalty = get_alliance_trust(dest_country, guard_country, alliances)
    guard_exit_penalty = get_alliance_trust(guard_country, exit_country, alliances)
    base_score *= client_exit_penalty * guard_dest_penalty * guard_exit_penalty
    return base_score

def select_path(clientIP, destIP, relays, reader, alliances, alpha_params={'safe_upper': 0.95, 
                                                                           'safe_lower': 2.0, 
                                                                           'accept_upper': 0.5, 
                                                                           'accept_lower': 5.0, 
                                                                           'bandwidth_frac': 0.2}):
    # Select a path based on the client IP, destination IP, and available relays.
    # Uses guard and exit security functions to filter and score relays.
    
    # Filter relays based on alpha parameters
    # relays = filter_relays(path, relays, alpha_params) if path else relays

    # If no path is provided, use all relays
    # path = path if path else (relays if not alpha_params else {
    # SUGGESTED_GUARD_PARAMS = {
    # ’safe_upper ’: 0.95 ,
    # ’safe_lower ’: 2.0 ,
    # ’accept_upper ’: 0.5 ,
    # ’accept_lower ’: 5.0 ,
    # ’ bandwidth_frac ’: 0.2
    # }

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
    guards = guard_security(clientIP, relays, alliances, reader)
    for g in guards:
        print(g[0]['fingerprint'], g[1])  # Debugging output for guard fingerprints and scores
    exits = {} # Dictionary to hold exit scores, fingerprint as key, score as value
    pairs = []
    # For each guard, calculate exit security and update the exits dictionary
    for guard, guard_score in guards:
        guard_fingerprint = guard['fingerprint']
        # For each guard, calculate exit security
        # and update the exits dictionary
        for relay in relays:
            if relay['fingerprint'] != guard_fingerprint:  # Avoid self-pairing
                score = exit_security(clientIP, destIP, guard, relay, alliances, reader)
                if score > 0:  # Only consider positive scores
                    exits[relay['fingerprint']] = score
    if not exits or not guards:
        return  None  # No valid exits or guards found
    
    
    return exits

def filter_relays(path, relays, alpha_params):
    # Filter relays based on the path and alpha parameters
    return None
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
    print("Country Trust Map:", country_trust_map)
    guard, exits = select_path(client_ip, dest_ip, relays, reader, alliances)

if __name__ == "__main__":
    main()