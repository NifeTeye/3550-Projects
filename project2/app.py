# app.py
from flask import Flask, jsonify, request
import sqlite3
from db import create_tables, generate_and_save_keys, DB_PATH, get_jwks_keys
from jwt_utils import authenticate_user

app = Flask(__name__)

@app.route('/auth', methods=['POST'])
def auth():
    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)
    generate_and_save_keys(conn)
    return authenticate_user(conn)

@app.route('/.well-known/jwks.json')  
def jwks():
    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)
    return jsonify({'keys': get_jwks_keys(conn)})

if __name__ == '__main__':
    app.run(port=8080)

