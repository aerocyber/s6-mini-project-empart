import bson.json_util
from flask import Blueprint, request, make_response, redirect, render_template, session, url_for
from werkzeug.security import check_password_hash
import random
from data import verify_jwt_token, generate_jwt_token, decode_jwt_token
from dotenv import load_dotenv
from os import environ
import datetime
from db import HospitalDB, StaffDB, PrivateRecordDB, PublicRecordDB, GeneratedPatientID
import bson
import re

staff_token_list = {}


load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

staff_routing = Blueprint('staff_form', __name__)

def generate_patient_id(hospital_id):
    ran = hospital_id + '-'
    for i in range(5):
        ran += str(random.randint(0, 9))

    fnd = False
    for i in GeneratedPatientID().get_ids(hospital_id):
        if i['id'] == ran:
            fnd = True
            break

    if PrivateRecordDB().get_record(ran) or fnd:
        return generate_patient_id(hospital_id)
    return ran

    
# Index route
@staff_routing.route('/')
def index():
    pid = request.args.get('pid') or None
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            hdb = HospitalDB()
            h = []
            for i in hdb.get_hospitals():
                h.append([i['id'], i['name'], i['location']])
            if pid:
                return render_template('staff_index.html', hospital_list=h, pid=pid)
            if searcherr := request.args.get('searcherr'):
                return render_template('staff_index.html', hospital_list=h, searcherr=searcherr)
            return render_template('staff_index.html', hospital_list=h)
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
        hdb = HospitalDB()
        user = db.get_staff(username)
        
        if not user or not db.check_password(username, password):
            # flash('Invalid username or password')
            print('Invalid username or password') # FIXME: REMOVE THIS
            return render_template('staff_login.html', err='Invalid username or password')
        token = generate_jwt_token(username, password, 'staff')
        response = make_response(redirect('/staff'))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('role', 'staff', expires=datetime.datetime.now() + datetime.timedelta(days=15))
        if 'username' not in session:
            session['username'] = {'username': username, 'ids': []}
        h = hdb.get_hospital_by_id(user['hospital_id'])
        print(h) # FIXME: REMOVE THIS
        g = GeneratedPatientID()
        for i in range(10):
            id_tmp = generate_patient_id(h['id'])
            g.add_id(h['id'], id_tmp)
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
        hdb = HospitalDB()
        
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff(request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        patient_name = request.form['patient_name']
        patient_age = request.form['patient_age']
        patient_blood_group = request.form['patient_blood_group']
        # patient_id = generate_patient_id(user['hospital_id'])
        
        patient_id = session['username']['ids'].pop()
        g = GeneratedPatientID()
        g.remove_id(patient_id)
        x = generate_patient_id(hdb.get_hospital_by_id(user['hospital_id'])['id'])
        session['username']['ids'].append(x)
        g.add_id(x, hdb.get_hospital_by_id(user['hospital_id'])['id'])
        patient_medication = request.form['patient_medication']
        patient_diagnosis = request.form['patient_diagnosis']
        patient_current_condition = request.form['patient_current_condition']
        patient_gender  = request.form['patient_gender']
        patient_weight = request.form['patient_weight'] or 'Not Available'
        from_hospital_id = user['hospital_id']
        to_hospital_id = request.form['to_hospital_id']
        notes = request.form['notes'] or 'None'

        # TODO: Add patient password to calling of db.
        priv = PrivateRecordDB()
        pub = PublicRecordDB()

        pub.add_record(to_hospital_id, from_hospital_id, patient_id, patient_medication, patient_diagnosis, patient_current_condition)
        priv.add_record(notes, to_hospital_id, from_hospital_id, patient_name, patient_age, patient_blood_group, patient_id, patient_medication, patient_diagnosis, patient_current_condition, patient_gender, patient_weight)

        # return 'Record added', 200
        return redirect(url_for('staff_form.index', pid=patient_id))
    return render_template('staff_index.html')

# Get private record
@staff_routing.route('/get-record', methods=['POST', 'GET'])
def get_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff(request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        patient_id = request.form['patient_id']
        # patient_pswd = request.form['patient_pswd']
        priv = PrivateRecordDB() # TODO: Add patient password to calling of db.
        priv.complete_status(patient_id)
        record = priv.get_record(patient_id)
        # print(record) # FIXME: REMOVE THIS
        return bson.json_util.dumps(record), 200
    return render_template('get_record.html')

# Get public record
@staff_routing.route('/get-public-record', methods=['POST'])
def get_public_record():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff(request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        patient_id = request.form['patient_id']
        pub = PrivateRecordDB()
        s = StaffDB()
        hospital_id = s.get_staff(user['email'])['hospital_id']
        record = pub.get_record(patient_id)
        pub.complete_status(patient_id)
        return bson.json_util.dumps(record), 200
    
@staff_routing.route('/get-public-record/<patient_id>', methods=['GET'])
def get_public_record_by_id(patient_id):
    db = StaffDB()
    if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
        return 'Invalid token', 403
    user = db.get_staff(request.cookies.get('username'))
    if not user:
        return 'Invalid token', 403
    
    pub = PrivateRecordDB()
    s = StaffDB()
    # hospital_id = s.get_staff(user['email'])['hospital_id']
    record = pub.get_record(patient_id)
    # pub.complete_status(patient_id)
    return render_template('get_public_record.html', record=record)

# Get all public records
@staff_routing.route('/get-all-public-records', methods=['POST', 'GET'])
def get_all_public_records():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff( request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        pub = PublicRecordDB()
        s = StaffDB()
        hospital_id = s.get_staff(user['email'])['hospital_id']
        records = pub.get_records(hospital_id)
        print(bson.json_util.dumps(records)) # FIXME: REMOVE THIS
        return bson.json_util.dumps(records), 200
    
    db = StaffDB()
    if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
        return 'Invalid token', 403
    user = db.get_staff( request.cookies.get('username'))
    if not user:
        return 'Invalid token', 403
    
    pub = PublicRecordDB()
    s = StaffDB()
    hospital_id = s.get_staff(user['email'])['hospital_id']
    records = pub.get_records(hospital_id)
    return render_template('get_all_public_records.html', records=records)

@staff_routing.route('/search/', methods=['POST'])
def search():
    patient_id = request.form['patient_id']
    d = PublicRecordDB()
    record = d.get_record(patient_id)
    if record:
        return redirect(f'/staff/get-public-record/{patient_id}')
    return redirect(url_for('staff_form.index', searcherr='Record not found'))

@staff_routing.route('/change-password', methods=['POST', 'GET'])
def change_password():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff(request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        old_password = request.form['old-password'] or None
        new_password = request.form['new-password'] or None
        confirm_password = request.form['confirm-password'] or None

        if old_password == None or new_password == None or confirm_password == None:
            return render_template('new_pswd_staff.html', err='All fields are required')
        
        if not db.check_password(user['email'], old_password):
            return render_template('new_pswd_staff.html', err='Invalid password') # TODO
        
        if new_password != confirm_password:
            return render_template('new_pswd_staff.html', err='Passwords do not match')
        
        p = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'
        if not re.match(p, new_password):
            return render_template('new_pswd_staff.html', err='Invalid format for password')
        
        db.change_password(user['email'], new_password) # TODO
        return redirect('/staff')
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return render_template('new_pswd_staff.html')
        return redirect('/logout')
    return redirect('/staff/login')

@staff_routing.route('/update-status', methods=['POST'])
def update_status():
    if request.method == 'POST':
        db = StaffDB()
        if not verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'staff'):
            return 'Invalid token', 403
        user = db.get_staff(request.cookies.get('username'))
        if not user:
            return 'Invalid token', 403
        
        patient_id = request.form['patient-id']
        priv = PrivateRecordDB()
        pub = PublicRecordDB()
        priv.complete_status(patient_id)
        pub.complete_status(patient_id)
        return redirect('/staff')
    return render_template('staff_index.html')