from flask import Blueprint, request, session, g
from werkzeug.security import check_password_hash
import jwt
from dotenv import load_dotenv
from os import environ

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('No SECRET_KEY set for Flask application')

api = Blueprint('api', __name__)

@api.route('/ping')
def ping():
    return 'System operational'

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    db = g.db
    user = db.users.find_one({"id": data['id']})
    if not user or not check_password_hash(user['password'], data['password']):
        return 'Invalid credentials', 403
    token = generate_jwt_token(data)
    session['user'] = user['id']
    session['token'] = token
    return {"Auth token": token}
    
# @api.route('/register', methods=['POST'])
# def register():
#     data = request.get_json()
#     db = g.db
#     user = db.users.find_one({"email": data['email']})
#     if user:
#         return 'User already exists', 400
#     db.users.insert_one({'email': data['email'], 'password': generate_password_hash(data['password'])})
#     return 'User created', 201



@api.route('/logout')
def logout():
    if 'user' in session:
        del session['user']
    if 'token' in session:
        del session['token']
    return {}, 200

@api.route('/accept-patient')
def accept_patient(): # TODO: Implement patient acceptance logic
    return 'Patient accepted'

@api.route('/notify-hospital')
def notify(): # TODO: Implement notification logic for incoming patient
    return 'Notification sent'

def generate_jwt_token(data):
    payload = {"ID": data['id']}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'