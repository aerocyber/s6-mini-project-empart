from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import check_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ
import datetime
from data import get_db

hospital_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

hospital_routes = Blueprint('hospital_form', __name__)

@hospital_routes.route('/')
def index():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            return render_template('hospital_dashboard.html')
        return redirect('/logout')
    
    return redirect('/login')

@hospital_routes.route('/login', methods=['POST', 'GET'])
def hospital_login():
    if request.method == 'POST':
        if (request.cookies.get('Auth') and request.cookies.get('JWT')):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
                return redirect('/')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.hospitals.find_one({"email": username})
        if not user or not check_password_hash(user['password'], password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(user)
        response = make_response(redirect('/'))
        response.set_cookie('Auth', generate_auth_token(username), expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('Auth'):

        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            resp = make_response(redirect('/'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            return resp
        
        return redirect('/logout')
    return render_template('hospital_login.html')

@hospital_routes.route('/logout')
def hospital_logout():
    resp = make_response(redirect('/login'))
    resp.delete_cookie('Auth')
    resp.delete_cookie('JWT')
    resp.delete_cookie('username')
    return resp

@hospital_routes.route('/add-keypair', methods=['POST', 'GET'])
def add_keypair():
    if request.method == 'POST':
        if not request.cookies.get('Auth') or not request.cookies.get('JWT') or not request.cookies.get('username'):
            resp = make_response(redirect('/login'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            resp.delete_cookie('username')
            return resp
        if not verify_jwt_token(request.cookies.get('JWT')) or not verify_auth_token(request.cookies.get('Auth')):
            return redirect('/logout')
        
        db = get_db()
        hospital = db.hospitals.find_one({"email": request.cookies.get('username')})
        if not hospital:
            return 'Hospital not found', 404
        keypair = {
            "public_key": request.form['public_key'],
            "private_key": request.form['private_key']
        }
        db.hospitals.update_one({"email": hospital['email']}, {"$set": {"keypair": keypair}})
        return 'Key pair added successfully', 201
    
    return render_template('add_keypair.html')

@hospital_routes.route('/add-staff', methods=['POST', 'GET'])
def add_staff():
    if request.method == 'POST':
        if not request.cookies.get('Auth') or not request.cookies.get('JWT') or not request.cookies.get('username'):
            resp = make_response(redirect('/login'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            resp.delete_cookie('username')
            return resp
        if not verify_jwt_token(request.cookies.get('JWT')) or not verify_auth_token(request.cookies.get('Auth')):
            return redirect('/logout')
        
        db = get_db()
        hospital = db.hospitals.find_one({"email": request.cookies.get('username')})
        if not hospital:
            return 'Hospital not found', 404
        staff = {
            "name": request.form['name'],
            "email": request.form['email'],
            "password": request.form['password']
        }
        db.hospitals.update_one({"email": hospital['email']}, {"$push": {"staff": staff}})
        return 'Staff added successfully', 201
    
    return render_template('add_staff.html')

@hospital_routes.route('/profile')
def hospital_profile():
    if not request.cookies.get('Auth') or not request.cookies.get('JWT') or not request.cookies.get('username'):
        resp = make_response(redirect('/login'))
        resp.delete_cookie('Auth')
        resp.delete_cookie('JWT')
        resp.delete_cookie('username')
        return resp
    if not verify_jwt_token(request.cookies.get('JWT')) or not verify_auth_token(request.cookies.get('Auth')):
        return redirect('/logout')
    
    db = get_db()
    hospital = db.hospitals.find_one({"email": request.cookies.get('username')})
    return render_template('hospital_profile.html', hospital=hospital)

# Helper functions

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
    

def verify_auth_token(token, username):
    token_format = token.split('.')
    if len(token_format) != 3:
        return False
    if token_format[0] != username:
        return False
    if token_format[1] < str(datetime.datetime.now()):
        return False
    if token_format[2] in hospital_token_list[username]:
        return False
    return True

def generate_auth_token(username):
    token = f"{username}.{datetime.datetime.now() + datetime.timedelta(days=15)}.{random.randint(100000, 999999)}"
    hospital_token_list[username].append(token)
    return token