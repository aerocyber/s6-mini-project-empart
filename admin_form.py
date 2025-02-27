import bson.json_util
from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import generate_password_hash
import random
import json
from dotenv import load_dotenv
from os import environ
import datetime
from db import HospitalDB, AdminDB
from data import generate_jwt_token, verify_jwt_token
import bson

hospitalDb = HospitalDB()
adminDB = AdminDB()

admin_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')
ADMIN_USER = environ.get('ADMIN_USERNAME')
ADMIN_PASS = environ.get('ADMIN_PASSWORD')

admin_routing = Blueprint('admin_form', __name__)

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
    if request.cookies.get('JWT') and verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
        h = HospitalDB()
        # hospital_list = bson.json_util.dumps(h.get_hospitals())
        hospital_list = []
        for i in h.get_hospitals():
            hospital_list.append([i['name'], i['id']])
        print(hospital_list)
        return render_template('admin_dashboard.html', hospital_list=hospital_list)
    if request.cookies.get('JWT'):
        return redirect('/logout')
    return redirect('/admin/login')


# Login route
@admin_routing.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
                return redirect('/admin')
            return redirect('/logout')
        username = request.form['email']
        password = request.form['password']
        # if username != ADMIN_USER or password != ADMIN_PASS:
        #     return 'Invalid credentials', 403

        if not adminDB.get_admin(username) or not adminDB.check_password(username, password):
            return render_template('admin_login.html', err="Incorrect credentials")
        user = {
            "id": 1,
            "username": username,
            "password": password
        }
        token = generate_jwt_token(username, password, 'admin')
        response = make_response(redirect('/admin'))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('role', 'admin', expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
            return redirect('/admin')
        return redirect('/logout')
    return render_template('admin_login.html')

# Add hospital route
@admin_routing.route('/add-hospital', methods=['POST', 'GET'])
def add_hospital():
    if request.method == 'GET':
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
            h = HospitalDB().get_hospitals()
            d = []
            for i in h:
                d.append(i['name'])
            return render_template('admin_add_hosp.html', hospitals=d)
        return redirect('/logout')
    if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
        hospital_name = request.form['name']
        hospital_id = generate_hospital_id(hospital_name)
        location = request.form['location']
        password = request.form['password']
        email = request.form['email']
        if hospitalDb.add_hospital(email, hospital_id, hospital_name, location, password) is not None:
            return 'Hospital already exists', 400
        return redirect('/admin')
    return redirect('/logout')



# Delete hospital route
@admin_routing.route('/delete-hospital', methods=['POST', 'GET'])
def delete_hospital():
    if request.method == 'GET':
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
            return redirect('/admin')
        return redirect('/logout')
    if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
        hospital_id = request.form['id']
        hospitalDb.remove_hospital(hospital_id)
        return redirect('/admin'), 200
    return redirect('/logout')

# Get hospital id
@admin_routing.route('/get-hospital-id', methods=['GET'])
def get_hospital_id():
    if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
        return redirect('/logout')
    id = generate_hospital_id(request.form.get('name'))
    # Check if hospital id exists
    if hospitalDb.get_hospital(id):
        return 'Hospital ID already exists', 400
    return id, 200

# Get all hospitals
@admin_routing.route('/get-hospitals', methods=['GET'])
def get_hospitals():
    if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'admin'):
        hospitals = bson.json_util.dumps(list(hospitalDb.get_hospitals()))
        return hospitals, 200
    return redirect('/logout')


# TESTED ^