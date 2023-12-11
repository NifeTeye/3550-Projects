from flask import Flask
import jwks
import auth

app = Flask(__name__)

@app.route('/jwks')
def jwks_endpoint():
  return jwks.get_jwks() 

@app.route('/auth')  
def auth_endpoint():
  # get credentials
  token = auth.authenticate(username, password)
  return token

if __name__ == '__main__':
  app.run()
