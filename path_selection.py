import json
import ipaddress
import random
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
        return 0.0 # country_trust_map[country]
    for alliance in alliances:
        if country1 in alliance['countries'] and country2 in alliance['countries']:
            return alliance['trust']
    return 1.0

def get_effective_bandwidth(relay):
    # Calculate the effective bandwidth of a relay.
    # Use measured bandwidth if available, otherwise use average bandwidth.
    if relay['bandwidth']['measured'] > 0:
        return relay['bandwidth']['measured']
    elif relay['bandwidth']['average'] > 0:
        return relay['bandwidth']['average']
    else:
        return 0.0

def bandwidth_weighted_choice(relays):
    total_bw = sum(get_effective_bandwidth(r) for r in relays)
    if total_bw == 0:
        return random.choice(relays)  # fallback

    r = random.uniform(0, total_bw)
    accum = 0
    for relay in relays:
        bw = get_effective_bandwidth(relay)
        accum += bw
        if accum >= r:
            return relay

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
    return sorted(scores, key=lambda x: x[1], reverse=True)  # Select top 10 guards


def exit_security ( client_loc , dest_loc , guard , exit , alliances , reader) :
    # Score exit relay based on guard / destination
    # check a pair of exit and guard relays

    # Anti AS,AUTO,FAMILY
    if(guard['fingerprint'] == exit['fingerprint'] or guard['asn'] == exit['asn'] or ('family' in guard and exit['fingerprint'] in guard['family'])):
        return 0.0
    parts = dest_loc.split(':')
    dest_ip = parts[0]
    dest_port = int(parts[1]) if len(parts) == 2 else None
    parts = client_loc.split(':')
    client_ip = parts[0]
    client_port = int(parts[1]) if len(parts) == 2 else None
    
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
    client_country = get_country(client_ip, reader)
    dest_country = get_country(dest_ip, reader)

    base_score = min(get_country_trust(exit_country), get_country_trust(guard_country))
    
    client_exit_penalty = get_alliance_trust(client_country, exit_country, alliances)
    guard_dest_penalty = get_alliance_trust(dest_country, guard_country, alliances)
    guard_exit_penalty = get_alliance_trust(guard_country, exit_country, alliances)
    base_score *= client_exit_penalty * guard_dest_penalty * guard_exit_penalty
    return base_score

def is_relay_compatible (relay_score, best_score, upper,lower):
    return relay_score >= best_score * upper  and \
            (1 - relay_score) <= (1 - best_score) * lower

def filter_relays(relay_scores, alpha_params,global_bandwidth):
    safe_upper = alpha_params['safe_upper']
    safe_lower = alpha_params['safe_lower']
    accept_upper = alpha_params['accept_upper']
    accept_lower = alpha_params['accept_lower']
    max_bandwidth = alpha_params['bandwidth_frac']* global_bandwidth

    safe = []
    acceptable = [] 
    best_score = relay_scores[0][1]
    for (relay, score) in relay_scores:
        if(max_bandwidth > 0):
            bandwidth = get_effective_bandwidth(relay)
            if is_relay_compatible(score, best_score, safe_upper, safe_lower):
                safe.append((relay, score))
                max_bandwidth -= bandwidth
            elif is_relay_compatible(score, best_score, accept_upper, accept_lower):
                acceptable.append((relay, score))
                max_bandwidth -= bandwidth
        else:
            break
    
    return safe, acceptable

def select_path(clientIP, destIP, relays, reader, alliances,global_bandwidth, alpha_params={'guard_params': 
                                                                           {'safe_upper': 0.95, 
                                                                                'safe_lower': 2.0, 
                                                                                'accept_upper': 0.5, 
                                                                                'accept_lower': 5.0, 
                                                                                'bandwidth_frac': 0.5
                                                                            }, 
                                                                           'exit_params': {
                                                                                'safe_upper': 0.95,
                                                                                'safe_lower': 2.0,
                                                                                'accept_upper': 0.1,
                                                                                'accept_lower': 10.0,
                                                                                'bandwidth_frac': 0.5
                                                                            }}):
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
    SAFE_GUARD_COUNT = 3
    ACCEPTABLE_GUARD_COUNT = 20
    MAX_ATTEMPTS = 5
    best_guard_exit = {}
    guard_params = alpha_params['guard_params']
    exit_params = alpha_params['exit_params']
    guards = guard_security(clientIP, relays, alliances, reader) # Ordered list of guards with scores
    if not guards:
        return None  # No valid guards found
    attempt = 0
    def relax_params(params):
        # Relax the parameters for the next attempt
        params['accept_upper'] /= 2.0
        params['accept_lower'] *= 2.0
        return params
    while attempt < MAX_ATTEMPTS and len(best_guard_exit) < SAFE_GUARD_COUNT:
        safe_guards, acceptable_guards = filter_relays(guards, guard_params, global_bandwidth)
        print("Safe Guards:", len(safe_guards), "Acceptable Guards:", len(acceptable_guards))
    
        if (not safe_guards and not acceptable_guards) or (len(safe_guards) < SAFE_GUARD_COUNT and len(acceptable_guards) < ACCEPTABLE_GUARD_COUNT):
            # No acceptable guards even with relaxed policy
            guard_params = relax_params(guard_params)
            attempt += 1
            continue
        
        # print("Safe Guards:", len(safe_guards), "Acceptable Guards:", len(acceptable_guards))
        # sum_bandwidth = sum(
        #     guard['bandwidth']['measured'] if guard['bandwidth']['measured'] > 0 else guard['bandwidth']['average']
        #     for guard in safe_guards
        # )
        # print("Total Safe Guard Bandwidth:", sum_bandwidth)
        # print("Fraction of Global Bandwidth:", sum_bandwidth / global_bandwidth)
        if len(safe_guards) >= ACCEPTABLE_GUARD_COUNT:
            selected_guards = safe_guards[:ACCEPTABLE_GUARD_COUNT]
        else:
            selected_guards = safe_guards + acceptable_guards[:ACCEPTABLE_GUARD_COUNT - len(safe_guards)]
        for (guard, guard_score) in selected_guards:
            exits = []
            # For each guard, calculate exit security
            # and update the exits dictionary
            for relay in relays:
                if relay['fingerprint'] != guard['fingerprint']:
                    score = exit_security(clientIP, destIP, guard, relay, alliances, reader)
                    if score > 0:
                        exits.append((relay, score))
            exits.sort(key=lambda x: x[1], reverse=True)
            if exits:  # If we have exits for this guard
                # safe_exits, acceptable_exits = filter_relays(exits, exit_params, global_bandwidth)
                # print("Safe Exits:", len(safe_exits), "Acceptable Exits:", len(acceptable_exits))
                # sum_bandwidth = sum(
                #     exit['bandwidth']['measured'] if exit['bandwidth']['measured'] > 0 else exit['bandwidth']['average']
                #     for exit in safe_exits
                # )
                # print("Total Safe Exit Bandwidth:", sum_bandwidth)
                # print("Fraction of Global Bandwidth:", sum_bandwidth / global_bandwidth)
                best_exit = exits[0][0]
                best_exit_score = exits[0][1]
                bandwidth_score = min(get_effective_bandwidth(best_exit), get_effective_bandwidth(guard))
                guard_exit_score = min(guard_score, best_exit_score) ** 4 * bandwidth_score
                best_guard_exit[f'{guard['fingerprint']}|{best_exit['fingerprint']}'] = guard_exit_score
                print(f"Guard {guard['fingerprint']} has safe exit {exits[0][0]['fingerprint']}")
                continue
        if len(best_guard_exit) >= ACCEPTABLE_GUARD_COUNT:
            print(f"Found {len(best_guard_exit)} valid guard-exit pairs.")
            break
        print(f"Attempt {attempt + 1}: No valid guard-exit pair found, relaxing parameters...")
        guard_params = relax_params(guard_params)
        attempt += 1

    if not best_guard_exit:
        print("No valid guard-exit pairs found after all attempts.")
        return  None  # No valid exits or guards found

    # Select the best guard-exit pair based on the highest score
    best_guard_exit = sorted(best_guard_exit.items(), key=lambda x: x[1], reverse=True)

    for guard_exit in best_guard_exit:
        guard_fingerprint, exit_fingerprint = guard_exit[0].split('|')
        print(f"Selected Guard: {guard_fingerprint}, Exit: {exit_fingerprint}, Score: {guard_exit[1]}")
        guard = next((g for g in relays if g['fingerprint'] == guard_fingerprint), None)
        exit = next((e for e in relays if e['fingerprint'] == exit_fingerprint), None)
        valid_middles = [
            r for r in relays 
            if r['fingerprint'] != guard_fingerprint and r['fingerprint'] != exit_fingerprint 
            and not r['fingerprint'] in guard['family'] and not r['fingerprint'] in exit['family'] 
            and r['asn'] != guard['asn'] and r['asn'] != exit['asn']
        ]
        if valid_middles:
            middle = bandwidth_weighted_choice(valid_middles)
            if middle:
                return guard, middle, exit

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
    global_bandwidth = sum(
        relay['bandwidth']['measured'] if relay['bandwidth']['measured'] > 0 else relay['bandwidth']['average']
        for relay in relays
    )
    print("Global Bandwidth:", global_bandwidth)

    guard, middle, exit = select_path(client_ip, dest_ip, relays, reader, alliances, global_bandwidth)

    if guard and middle and exit:
        print(f"Selected Guard: {guard['fingerprint']}, Middle Relay: {middle['fingerprint']}, Exit: {exit['fingerprint']}")
    else:
        print("No valid path found.")

if __name__ == "__main__":
    main()