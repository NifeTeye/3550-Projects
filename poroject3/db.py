# db.py
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.backends import default_backend
import time
import base64

DB_PATH = "totally_not_my_privateKeys.db"
GOOD_KEY_PATH = "good_key.pem"
EXPIRED_KEY_PATH = "expired_key.pem"

def create_tables(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL, 
            exp INTEGER NOT NULL
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

def generate_and_save_keys(conn):
    now = int(time.time())
    
    # Generate keys
    key1 = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
        backend=default_backend()  
    )
    key2 = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
        backend=default_backend()
    )
    
    # Save non-expired key 
    insert_key(conn, key1, now + 3600)
    
    # Save expired key
    insert_key(conn, key2, now - 3600)

    # Save private keys to files
    with open(GOOD_KEY_PATH, 'wb') as good_key_file:
        good_key_file.write(key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(EXPIRED_KEY_PATH, 'wb') as expired_key_file:
        expired_key_file.write(key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
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
        cursor.execute('SELECT key FROM keys WHERE exp < ?',  
                     (int(time.time()),))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp > ?',  
                     (int(time.time()),))
                     
    row = cursor.fetchone()
    if row:
        return serialization.load_pem_private_key(
           row[0], password=None)

def get_jwks_keys(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', 
                 (int(time.time()),))
    keys = []
    
    for row in cursor:
        keys.append({
            'kid': row[0],
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

def register_user(conn):
    # Add your user registration logic here
    pass

def log_auth_request(conn, request_ip, user_id=None):
    conn.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))

