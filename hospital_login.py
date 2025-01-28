from flask import Blueprint, request, session, g
from werkzeug.security import check_password_hash
import jwt
from dotenv import load_dotenv
from os import environ

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

hospital = Blueprint('hospital', __name__)

@hospital.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    db = g.db
    user = db.hospitals.find_one({"email": data['email']})
    if not user or not check_password_hash(user['password'], data['password']):
        return 'Invalid credentials', 403
    token = generate_jwt_token(data)
    session['user'] = user['email']
    session['token'] = token
    return {"Auth token": token}

@hospital.route('/logout')
def logout():
    if 'user' in session:
        del session['user']
    if 'token' in session:
        del session['token']
    return {}, 200

@hospital.route('/register-staff', methods=['POST'])
def register_staff():
    data = request.get_json()
    db = g.db
    user = verify_jwt_token(data['token'])
    if not user:
        return 'Invalid token', 403
    db.staff.insert_one({'name': data['name'], 'id': data['id'], 'hospital': user['hospital']})
    return {"Status": "Success"}, 201

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