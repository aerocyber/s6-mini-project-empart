from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import check_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ
import datetime
from db import HospitalDB, StaffDB

hospital_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')
hospitalDb = HospitalDB()
staffDb = StaffDB()

hospital_routes = Blueprint('hospital_form', __name__)

# Generate JWT token
def generate_jwt_token(username, password):
    payload = {"user": username, 'password': password}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Verify JWT token
def verify_jwt_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

@hospital_routes.route('/')
def index():
    if request.cookies.get('JWT') and verify_jwt_token(request.cookies.get('JWT')):
        return render_template('hospital_dashboard.html')
    if request.cookies.get('JWT'):
        return redirect('/logout')
    return redirect('/hospital/login')

@hospital_routes.route('/login', methods=['POST', 'GET'])
def hospital_login():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT')):
                return redirect('/hospital')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        user = hospitalDb.get_hospital(username)
        if not user or not hospitalDb.check_password(username, password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(username, password)
        response = make_response(redirect('/hospital'))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT')):
            resp = make_response(redirect('/hospital'))
            resp.delete_cookie('JWT')
            return resp
        return redirect('/logout')
    return render_template('hospital_login.html')

@hospital_routes.route('/add-staff', methods=['POST', 'GET'])
def add_staff():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT')):
                staff_name = request.form['staff_name']
                staff_email = request.form['staff_email']
                staff_password = request.form['staff_password']
                hospital_id = jwt.decode(request.cookies.get('JWT'), SECRET_KEY, algorithms=['HS256'])['user']
                if staffDb.get_staff(staff_email):
                    return 'Staff already exists', 400
                staffDb.add_staff(staff_name, staff_email, staff_password, hospital_id)
                return 'Staff added successfully', 201
            return redirect('/logout')
        return redirect('/hospital/login')
    return render_template('add_staff.html')

@hospital_routes.route('/keypair', methods=['POST', 'GET'])
def add_keypair():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT')):
                public_key = request.form['public_key']
                private_key = request.form['private_key']
                hospital_id = jwt.decode(request.cookies.get('JWT'), SECRET_KEY, algorithms=['HS256'])['user']
                hospitalDb.add_keypair(hospital_id, public_key, private_key)
                return 'Key pair added successfully', 201
            return redirect('/logout')
        return redirect('/hospital/login')
    return render_template('add_keypair.html')