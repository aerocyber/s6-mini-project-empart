from dotenv import load_dotenv
from os import environ
import jwt
from hashlib import sha256

load_dotenv()
# MONGO_DB_CONNECTION_STRING = environ.get('MONGO_DB_CONNECTION_STRING')
# MONGO_DB_COLLECTION = environ.get('MONGO_DB_COLLECTION')
SECRET_KEY = environ.get('SECRET_KEY', None)

# if not MONGO_DB_CONNECTION_STRING:
#     raise ValueError('No MONGO_DB_CONNECTION_STRING set for Flask application')
# if not MONGO_DB_COLLECTION:
#     raise ValueError('No MONGO_DB_COLLECTION set for Flask application')
if SECRET_KEY is None:
    raise ValueError('No SECRET_KEY set for Flask application')


# def connect_to_database():
#     client = MongoClient(MONGO_DB_CONNECTION_STRING)
#     return client[MONGO_DB_COLLECTION]

# def get_db():
#     if 'db' not in g:
#         g.db = connect_to_database()
#     return g.db


def encrypt_record(record): # TODO: Implement encryption
    return record

def decrypt_record(record): # TODO: Implement decryption
    return record

# Decode JWT token
def decode_jwt_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
    
# Generate JWT token
def generate_jwt_token(username, password, role):
    payload = {"user": username, 'password': sha256(password.encode('utf-8')).hexdigest(), 'role': role}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Verify JWT token
def verify_jwt_token(token, username, role):
    try:
        x = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if x['user'] == username and x['role'] == role:
            return True
        return False
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False