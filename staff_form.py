from flask import Blueprint, request, make_response, redirect, render_template, session
from werkzeug.security import check_password_hash
import random
from data import verify_jwt_token, generate_jwt_token, decode_jwt_token
from dotenv import load_dotenv
from os import environ
import datetime
from db import StaffDB, PrivateRecordDB, PublicRecordDB

staff_token_list = {}

generated_ids = []

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

staff_routing = Blueprint('staff_form', __name__)

def generate_patient_id(hospital_id):
    ran = hospital_id + '-'
    for i in range(5):
        ran += str(random.randint(0, 9))

    if PrivateRecordDB().get_record(ran, hospital_id) or ran in generated_ids:
        return generate_patient_id(hospital_id)
    return ran

    
# Index route
@staff_routing.route('/')
def index():
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return render_template('staff_index.html')
        return redirect('/logout')
    return redirect('/staff/login')

# Login route
@staff_routing.route('/login', methods=['POST', 'GET'])
def staff_login():
    if request.method == 'POST':
        if request.cookies.get('JWT') and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
                return redirect('/staff')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        db = StaffDB()
        user = db.get_staff(username)
        if not user or not db.check_password(username, password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(username, password, 'staff')
        response = make_response(redirect('/staff'))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('role', 'staff', expires=datetime.datetime.now() + datetime.timedelta(days=15))
        if 'username' not in session:
            session['username'] = {'username': username, 'ids': []}
        for i in range(10):
            id_tmp = generate_patient_id(user['hospital_id'])
            generated_ids.append(id_tmp)
            session['username']['ids'].append(id_tmp)
        return response
    
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            resp = make_response(redirect('/staff'))
            return resp
        return redirect('/logout')
    return render_template('staff_login.html')

# Add a patient record to the database
@staff_routing.route('/add-record', methods=['POST', 'GET'])
def add_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.find_one({'username': request.cookies.get('username')})
        if not user:
            return 'Invalid token', 403
        
        patient_name = request.form['patient_name']
        patient_age = request.form['patient_age']
        patient_blood_group = request.form['patient_blood_group']
        # patient_id = generate_patient_id(user['hospital_id'])
        patient_id = session['username']['ids'].pop()
        session['username']['ids'].append(patient_id)
        patient_medication = request.form['patient_medication']
        patient_diagnosis = request.form['patient_diagnosis']
        patient_current_condition = request.form['patient_current_condition']
        patient_gender  = request.form['patient_gender']
        patient_weight = request.form['patient_weight']
        from_hospital_id = user['hospital_id']
        to_hospital_id = request.form['to_hospital_id']

        # TODO: Add patient password to calling of db.
        priv = PrivateRecordDB()
        pub = PublicRecordDB()

        pub.add_record(to_hospital_id, patient_id, patient_medication, patient_diagnosis, patient_current_condition)
        priv.add_record(to_hospital_id, from_hospital_id, patient_name, patient_age, patient_blood_group, patient_id, patient_medication, patient_diagnosis, patient_current_condition, patient_gender, patient_weight)

        return 'Record added', 200
    return render_template('add_record.html')

# Get private record
@staff_routing.route('/get-record', methods=['POST', 'GET'])
def get_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.find_one({'username': request.cookies.get('username')})
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
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.find_one({'username': request.cookies.get('username')})
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
        if not verify_jwt_token(request.cookies.get('JWT'), 'staff'):
            return 'Invalid token', 403
        user = db.find_one({'username': decode_jwt_token(request.cookies.get('JWT'))['user']})
        if not user:
            return 'Invalid token', 403
        
        pub = PublicRecordDB()
        s = StaffDB()
        hospital_id = s.get_staff(user['email'])['hospital_id']
        records = pub.get_all_records(hospital_id)
        return records, 200
    return render_template('get_all_public_records.html')


