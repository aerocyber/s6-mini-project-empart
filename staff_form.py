from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import check_password_hash
import random
import jwt
from dotenv import load_dotenv
from os import environ
import datetime
from db import StaffDB, PrivateRecordDB, PublicRecordDB

staff_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

staff_routing = Blueprint('staff_form', __name__)

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
    
def generate_patient_id():
    ran = ""
    
# Index route
@staff_routing.route('/')
def index():
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT')):
            return render_template('staff_index.html')
        return redirect('/staff/logout')
    return redirect('/staff/login')

# Login route
@staff_routing.route('/login', methods=['POST', 'GET'])
def staff_login():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT')):
                return redirect('/staff')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        db = StaffDB()
        user = db.get_staff(username)
        if not user or not db.check_password(username, password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(user)
        response = make_response(redirect('/staff'))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT')):
            resp = make_response(redirect('/staff'))
            return resp
        return redirect('/logout')
    return render_template('staff_login.html')

# Add a patient record to the database
@staff_routing.route('/add-record', methods=['POST', 'GET'])
def add_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT')):
            return 'Invalid token', 403
        user = db.find_one({'username': verify_jwt_token(request.cookies.get('JWT'))['user']})
        if not user:
            return 'Invalid token', 403
        
        patient_name = request.form['patient_name']
        patient_age = request.form['patient_age']
        patient_blood_group = request.form['patient_blood_group']
        patient_id = request.form['patient_id'] # TODO: Generate a unique patient ID
        patient_medication = request.form['patient_medication']
        patient_diagnosis = request.form['patient_diagnosis']
        patient_current_condition = request.form['patient_current_condition']
        patient_gender  = request.form['patient_gender']
        patient_weight = request.form['patient_weight']

        # TODO: Add patient password to calling of db.
        priv = PrivateRecordDB()
        pub = PublicRecordDB()

        pub.add_record(patient_id, patient_medication, patient_diagnosis, patient_current_condition)
        priv.add_record(patient_name, patient_age, patient_blood_group, patient_id, patient_medication, patient_diagnosis, patient_current_condition, patient_gender, patient_weight)

        return 'Record added', 200
    return render_template('add_record.html')

# Get private record
@staff_routing.route('/get-record', methods=['POST', 'GET'])
def get_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT')):
            return 'Invalid token', 403
        user = db.find_one({'username': verify_jwt_token(request.cookies.get('JWT'))['user']})
        if not user:
            return 'Invalid token', 403
        
        patient_id = request.form['patient_id']
        patient_pswd = request.form['patient_pswd']
        priv = PrivateRecordDB() # TODO: Add patient password to calling of db.
        record = priv.get_record(patient_id)
        return record, 200
    return render_template('get_record.html')

# Get public record
@staff_routing.route('/get-public-record', methods=['POST', 'GET'])
def get_public_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT')):
            return 'Invalid token', 403
        user = db.find_one({'username': verify_jwt_token(request.cookies.get('JWT'))['user']})
        if not user:
            return 'Invalid token', 403
        
        patient_id = request.form['patient_id']
        pub = PublicRecordDB()
        s = StaffDB()
        hospital_id = s.get_staff(user['email'])['hospital_id']
        record = pub.get_record(patient_id, hospital_id)
        return record, 200
    return render_template('get_public_record.html')

# Get all public records
@staff_routing.route('/get-all-public-records', methods=['POST', 'GET'])
def get_all_public_records():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT')):
            return 'Invalid token', 403
        user = db.find_one({'username': verify_jwt_token(request.cookies.get('JWT'))['user']})
        if not user:
            return 'Invalid token', 403
        
        pub = PublicRecordDB()
        s = StaffDB()
        hospital_id = s.get_staff(user['email'])['hospital_id']
        records = pub.get_all_records(hospital_id)
        return records, 200
    return render_template('get_all_public_records.html')


