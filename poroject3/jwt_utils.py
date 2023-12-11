# jwt_utils.py
from flask import jsonify, request
import jwt
from db import get_private_key

def authenticate_user(conn):
    username = request.args.get('username')  
    expired = request.args.get('expired')
    
    key = get_private_key(conn, expired=expired)
    
    if key:
        payload = {'user': username}
        return jwt.encode(payload, key, algorithm='RS256') 
    else:
        return jsonify({'error':'Private key not found'}), 400
