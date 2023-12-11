# Implements JWKS generation and retrieval 

keys = [...] # generated keys

def get_jwks():
  # filter for unexpired keys
  jwks = {'keys': unexpired_keys}
  return jwks
