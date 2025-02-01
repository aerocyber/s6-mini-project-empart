from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import check_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ
import datetime
from data import get_db

admin_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

admin_routing = Blueprint('admin_form', __name__)

# Index route

@admin_routing.route('/') # TODO: Admin Index rendering
def index():
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            return render_template('admin_index.html') # TODO: Create update index
        return redirect('/logout')
    
    return redirect('/login')

# Login and Logout routes

@admin_routing.route('/login', methods=['POST', 'GET'])
def admin_login():
    # Login logic
    if request.method == 'POST':
        if (request.cookies.get('Auth') and request.cookies.get('JWT')) and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
                return redirect('/')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.admins.find_one({"email": username})
        if not user or not check_password_hash(user['password'], password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(user)
        response = make_response(redirect('/'))
        response.set_cookie('Auth', generate_auth_token(username), expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('Auth'):

        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            resp = make_response(redirect('/'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            return resp
        
        return redirect('/logout')
    return render_template('admin_login.html')

@admin_routing.route('/logout')
def admin_logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('Auth')
    resp.delete_cookie('JWT')
    resp.delete_cookie('username')
    return resp

# Add hospital

@admin_routing.route('/add_hospital', methods=['POST', 'GET'])
def add_hospital():
    if request.method == 'GET':
        if request.cookies.get('Auth') and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
                return render_template('add_hospital.html')
            return redirect('/logout')
        return redirect('/login')
    
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            db = get_db()
            hospital_name = request.form['name']
            hospital_id = generate_hospital_id(hospital_name)
            location = request.form['location']
            hospital = {
                "name": hospital_name,
                "hospital_id": hospital_id,
                "location": location,
            }
            db.hospitals.insert_one(hospital)
            return 'Hospital added', 200
        return redirect('/logout')
    
    return redirect('/login')

@admin_routing.route('/delete_hospital', methods=['POST', 'GET'])
def delete_hospital():
    if request.method == 'GET':
        if request.cookies.get('Auth') and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
                return render_template('delete_hospital.html')
            return redirect('/logout')
        return redirect('/login')
    
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            db = get_db()
            hospital_name = request.form['name']
            db.hospitals.delete_one({"name": hospital_name})
            return 'Hospital deleted', 200
        return redirect('/logout')
    
    return redirect('/login')

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
    if token_format[2] in admin_token_list[username]:
        return False
    return True

def generate_auth_token(username):
    token = f"{username}.{datetime.datetime.now() + datetime.timedelta(days=15)}.{random.randint(100000, 999999)}"
    admin_token_list[username].append(token)
    return token