# test_auth.py
import unittest
from flask import Flask, jsonify
from app import app
from db import create_tables, generate_and_save_keys, DB_PATH

class TestAuth(unittest.TestCase):

    def setUp(self):
        app.testing = True
        self.app = app.test_client()

    def test_auth_valid_jwt_authn(self):
        response = self.app.get('/auth?username=oot0012')
        data = response.get_json()
        self.assertIn('user', data)

    # Add more test cases as needed

if __name__ == '__main__':
    unittest.main()
