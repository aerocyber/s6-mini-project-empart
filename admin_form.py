from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import generate_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ
import datetime
from db import HospitalDB

hospitalDb = HospitalDB()

admin_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')
ADMIN_USER = environ.get('ADMIN_USERNAME')
ADMIN_PASS = environ.get('ADMIN_PASSWORD')

admin_routing = Blueprint('admin_form', __name__)

"""
# Index route

@admin_routing.route('/') # TODO: Admin Index rendering
def index():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        print('Auth token found')
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
            print('Auth token verified')
            return render_template('admin_dashboard.html')
        print(verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')))
        return redirect('/admin/logout')
    
    return redirect('/admin/login')

# Login and Logout routes

@admin_routing.route('/login', methods=['POST', 'GET'])
def admin_login():
    # Login logic
    if request.method == 'POST':
        if (request.cookies.get('Auth') and request.cookies.get('JWT')) and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
                return redirect('/admin')
            print('Invalid token')
            return redirect('/admin/logout')
        
        username = request.form['email']
        password = request.form['password']
        if username != ADMIN_USER or password != ADMIN_PASS:
            return 'Invalid credentials', 403
        user = {
            "id": 1,
            "username": username,
            "password": password
        }
        token = generate_jwt_token(user)
        response = make_response(redirect('/admin'))
        response.set_cookie('Auth', generate_auth_token(username), expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('Auth') and request.cookies.get('username'):

        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
            resp = make_response(redirect('/admin'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            resp.delete_cookie('username')
            return resp
        
        return redirect('/admin/logout')
    return render_template('admin_login.html')

@admin_routing.route('/logout')
def admin_logout():
    if admin_token_list.get(request.cookies.get('username')):
        _ = admin_token_list[request.cookies.get('username')].remove(request.cookies.get('Auth'))
    resp = make_response(redirect('/admin'))
    resp.delete_cookie('Auth')
    resp.delete_cookie('JWT')
    resp.delete_cookie('username')
    return resp

# Add hospital

@admin_routing.route('/add-hospital', methods=['POST', 'GET'])
def add_hospital():
    if request.method == 'GET':
        if request.cookies.get('Auth') and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
                return render_template('add_hospital.html')
            return redirect('/admin/logout')
        return redirect('/admin/login')
    
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
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
        return redirect('/admin/logout')
    
    return redirect('/admin/login')

@admin_routing.route('/delete-hospital', methods=['POST', 'GET'])
def delete_hospital():
    if request.method == 'GET':
        if request.cookies.get('Auth') and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
                return render_template('delete_hospital.html')
            return redirect('/admin/logout')
        return redirect('/admin/login')
    
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth'), request.cookies.get('username')):
            db = get_db()
            hospital_name = request.form['name']
            db.hospitals.delete_one({"name": hospital_name})
            return 'Hospital deleted', 200
        return redirect('/admin/logout')
    
    return redirect('/admin/login')

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
    payload = {"user": ADMIN_USER}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
    

def verify_auth_token(token, username):
    token_format = token.split('/')
    if len(token_format) != 3:
        return False
    if token_format[0] != username:
        return False
    if datetime.datetime.strptime(token_format[1], "%Y-%m-%d %H:%M:%S.%f") < datetime.datetime.now():
        return False
    if token_format[2] in admin_token_list[username]:
        return False
    return True

def generate_auth_token(username):
    token = f"{username}/{datetime.datetime.now() + datetime.timedelta(days=15)}/{random.randint(100000, 999999)}"
    if admin_token_list.get(username) is None:
        admin_token_list[username] = []
    admin_token_list[username].append(token)
    print(admin_token_list)
    return token
"""

# Generate JWT token
def generate_jwt_token(user):
    payload = {"user": user['username'], 'password': user['password']}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Verify JWT token
def verify_jwt_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
    

# Generate hospital ID
def generate_hospital_id(name):
    id = ''
    split_name = name.split()
    for word in split_name:
        id += word[0].upper()
    
    while len(id) < 11:
        id += str(random.randint(0, 9))

    return id

# Index route
@admin_routing.route('/')
def index():
    if request.cookies.get('JWT') and verify_jwt_token(request.cookies.get('JWT')):
        return render_template('admin_dashboard.html')
    if request.cookies.get('JWT'):
        return redirect('/logout')
    return redirect('/admin/login')


# Login route
@admin_routing.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            return redirect('/logout')
        username = request.form['email']
        password = request.form['password']
        if username != ADMIN_USER or password != ADMIN_PASS:
            return 'Invalid credentials', 403
        user = {
            "id": 1,
            "username": username,
            "password": password
        }
        token = generate_jwt_token(user)
        response = make_response(redirect('/admin'))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    if request.cookies.get('JWT'):
        return redirect('/logout')
    return render_template('admin_login.html')

# Add hospital route
@admin_routing.route('/add-hospital', methods=['POST'])
def add_hospital():
    if verify_jwt_token(request.cookies.get('JWT')):
        hospital_name = request.form['name']
        hospital_id = request.form['hospital_id']
        location = request.form['location']
        password = generate_password_hash(request.form['password'])
        hospitalDb.add_hospital(hospital_id, hospital_name, location, password)
        return 'Hospital added', 200
    return redirect('/logout')



# Delete hospital route
@admin_routing.route('/delete-hospital', methods=['POST'])
def delete_hospital():
    if verify_jwt_token(request.cookies.get('JWT')):
        hospital_id = request.form['id']
        hospitalDb.remove_hospital(hospital_id)
        return redirect('/admin'), 200
    return redirect('/logout')

# Get hospital id
@admin_routing.route('/get-hospital-id', methods=['GET'])
def get_hospital_id():
    id = generate_hospital_id(request.get_json.get('name'))
    # Check if hospital id exists
    if hospitalDb.get_hospital(id):
        return 'Hospital ID already exists', 400
    return id, 200