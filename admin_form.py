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