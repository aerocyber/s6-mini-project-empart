from flask import Blueprint, request, g, session
from werkzeug.security import check_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

admin = Blueprint('admin', __name__)

@admin.route('/accept-hospital', methods=['POST'])
def accept_hospital():
    data = request.get_json()
    db = g.db
    user = verify_jwt_token(data['token'])
    if not user:
        return 'Invalid token', 403
    db.hospitals.insert_one({'name': data['name'], 'address': data['address'], 'ID': generate_hospital_id(data['name'])})
    return {"Status": "Success"}, 201

@admin.route('/unregister-hospital', methods=['POST'])
def unregister_hospital():
    data = request.get_json()
    db = g.db
    user = verify_jwt_token(data['token'])
    if not user:
        return 'Invalid token', 403
    db.hospitals.delete_one({'ID': data['ID']})
    return {"Status": "Success"}, 200

@admin.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    db = g.db
    user = db.admins.find_one({"email": data['email']})
    if not user or not check_password_hash(user['password'], data['password']):
        return 'Invalid credentials', 403
    token = generate_jwt_token(data)
    session['user'] = user['email']
    session['token'] = token
    return {"Auth token": token}

@admin.route('/logout')
def logout():
    if 'user' in session:
        del session['user']
    if 'token' in session:
        del session['token']
    return {}, 200

def generate_hospital_id(name):
    id = ''
    c = 0
    while c < 11:
        if c < 3:
            if name[c].isalpha():
                id += name[c].upper()
                c += 1
                continue
        if c >= 3:
            c += random.randint(0, 9)
        c += 1

    return id

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