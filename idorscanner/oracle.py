"""
Runs mutated requests
Compares attacker response with original baseline:
    Status codes
    JSON/HTML semantic diff
    Owner marker mismatch

Returns verdict: NO_IDOR, POSSIBLE_IDOR, CONFIRMED_IDOR
"""
