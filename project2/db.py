lization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def insert_key(conn, key, exp):
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                 (key.private_bytes(
                      encoding=serialization.Encoding.PEM,
                      format=serialization.PrivateFormat.PKCS8, 
                      encryption_algorithm=serialization.NoEncryption()),  
                  exp))

def get_private_key(conn, expired=False):
    cursor = conn.cursor()
    if expired: 
        cursor.execute('SELECT kid, key FROM keys WHERE exp < ?',  
                     (int(time.time()),))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ?',  
                     (int(time.time()),))
                     
    row = cursor.fetchone()
    if row:
        key = serialization.load_pem_private_key(
           row[1], password=None)
        key.kid = str(row[0])  # Convert kid to string and set kid attribute
        return key

def get_jwks_keys(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', 
                 (int(time.time()),))
    keys = []
    
    for row in cursor:
        keys.append({
            'kid': str(row[0]),
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig', 
            'n': serialize_public_key(row[1]),  
        })
        
    return keys
    
def serialize_public_key(pem_key):
    key = serialization.load_pem_private_key(
       pem_key, password=None)
    nums = key.public_key().public_numbers()  
    data = nums.n.to_bytes(256, 'big')
    return base64.urlsafe_b64encode(data).decode()

