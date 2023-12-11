# jwt_utils.py
from flask import jsonify, request
import jwt
from db import get_private_key

def authenticate_user(conn):
    if request.method == 'POST':
        # Assuming the username is sent in the request data for a POST request
        username = request.form.get('username')
        expired = request.form.get('expired')
    else:
        # Assuming the username is sent as a query parameter for a GET request
        username = request.args.get('username')
        expired = request.args.get('expired')

    key = get_private_key(conn, expired=expired)

    if key:
        payload = {'user': username}
        headers = {'kid': str(key.kid)}  # Convert kid to string
        token = jwt.encode(payload, key, algorithm='RS256', headers=headers)
        return jsonify({'jwt': token})
    else:
        return jsonify({'error': 'Private key not found'}), 400

