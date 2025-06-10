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