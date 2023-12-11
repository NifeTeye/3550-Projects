import unittest
from test_jwks import TestJWKS 
from test_auth import TestAuth

# Test suite 
suite = unittest.TestSuite()
suite.addTest(unittest.makeSuite(TestJWKS))
suite.addTest(unittest.makeSuite(TestAuth))

if __name__ == '__main__':
   unittest.main()
