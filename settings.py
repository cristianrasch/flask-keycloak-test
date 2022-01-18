import os
import secrets

from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex())
PREFERRED_URL_SCHEME = os.getenv('PREFERRED_URL_SCHEME', 'http')
SERVER_NAME = os.getenv('SERVER_NAME', 'localhost:5000')
CLIENT_ID = os.getenv('CLIENT_ID', '')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', '')
REDIRECT_URI = os.getenv('REDIRECT_URI',
                         f"{PREFERRED_URL_SCHEME}://{SERVER_NAME}/callback")
ISSUER_ID = os.getenv('ISSUER_ID', 'https://localhost:8443/auth/realms/test/')
TOKEN_ENDPOINT = os.getenv('TOKEN_ENDPOINT', 'protocol/openid-connect/token')
LOGOUT_ENDPOINT = os.getenv('LOGOUT_ENDPOINT', 'protocol/openid-connect/logout')
