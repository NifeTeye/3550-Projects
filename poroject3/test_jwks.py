# test_jwks.py
import unittest
from flask import Flask, jsonify
from app import app
from db import create_tables, generate_and_save_keys, DB_PATH

class TestJWKS(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.app = app.test_client()

    def test_valid_jwk_found_in_jwks(self):
        response = self.app.get('/.well-known/jwks.json')
        data = response.get_json()
        self.assertIn('keys', data)

    # Add more test cases as needed

if __name__ == '__main__':
    unittest.main()
