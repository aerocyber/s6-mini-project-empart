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

"""
# Index route

@staff_routing.route('/') # TODO: Staff Index rendering
def index():
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            return render_template('staff_index.html')
        return redirect('/staff/logout')
    
    return redirect('/staff/login')

# Login and Logout routes

@staff_routing.route('/login', methods=['POST', 'GET'])
def staff_login():
    # Login logic
    if request.method == 'POST':
        if (request.cookies.get('Auth') and request.cookies.get('JWT')) and request.cookies.get('username'):
            if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
                return redirect('/staff')
            return redirect('/staff/logout')
        
        username = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.staff.find_one({"email": username})
        if not user or not check_password_hash(user['password'], password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(user)
        response = make_response(redirect('/staff'))
        response.set_cookie('Auth', generate_auth_token(username), expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('Auth') and request.cookies.get('username'):

        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            resp = make_response(redirect('/staff'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            return resp
        
        return redirect('/staff/logout')
    return render_template('staff_login.html')

@staff_routing.route('/logout')
def staff_logout():
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            staff_token_list[request.cookies.get('username')].pop(request.cookies.get('Auth'))
            resp = make_response(redirect('/staff'))
            resp.delete_cookie('Auth')
            resp.delete_cookie('JWT')
            resp.delete_cookie('username')
            return resp
        return redirect('/staff/login')
    return redirect('/staff/login')

# Staff profile
@staff_routing.route('/profile')
def staff_profile():
    if request.cookies.get('Auth'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            return render_template('staff_profile.html')
        return redirect('/staff/logout')
    return redirect('/staff/login')

# Staff edit profile
@staff_routing.route('/edit-profile', methods=['POST', 'GET'])
def staff_edit_profile():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            if request.method == 'GET':
                return render_template('staff_edit_profile.html')
            
            # Edit profile logic
            new_data = {
                "name": request.form['name'],
                "email": request.form['email'],
                "password": request.form['password']
            }
            db = get_db()
            db.staff.update_one({"email": request.cookies.get('username')}, {"$set": new_data})
            return redirect('/staff/profile')
        
        return redirect('/staff/logout')
    return redirect('/staff/login')

# Send record to hospital in encrypted format
@staff_routing.route('/send-record', methods=['POST', 'GET'])
def send_record():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            if request.method == 'GET':
                return render_template('send_record.html')
            
            # Send record logic
            db = get_db()
            hospital = db.hospitals.find_one({"id": request.form['hospital-id']})
            if not hospital:
                return 'Hospital not found', 404
            record = {
                "id": request.form['id'],
                "condition": request.form['condition'],
                "medication": request.form['medication'],
                "to hospital": hospital['hospital_id'],
                "age": request.form['age'],
                "notes": request.form['notes'],
                "date": datetime.datetime.now(),
            }

            # Encrypt record with gpg
            encrypted_record = encrypt_record(record, hospital['keypair']['public_key'])


            db.transfers.insert_one({record})
            return 'Record sent', 200
        
        return redirect('/staff/logout')
    return redirect('/staff/login')

# View all records
@staff_routing.route('/view-records')
def staff_view_records():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            db = get_db()
            hospital = db.staff.find_one({"email": request.cookies.get('username')})['hospital_id']
            records = db.transfers.find({"from hospital": hospital})
            return render_template('view_records.html', records=records, decrypt_record=decrypt_record)
        return redirect('/staff/logout')
    return redirect('/staff/login')

@staff_routing.route('/view-records-alert')
def view_records():
    if request.cookies.get('Auth') and request.cookies.get('username'):
        if verify_jwt_token(request.cookies.get('JWT')) and verify_auth_token(request.cookies.get('Auth')):
            db = get_db()
            hospital = db.staff.find_one({"email": request.cookies.get('username')})['hospital_id']
            records = db.transfers.find({"from hospital": hospital})
            return records
        return redirect('/staff/logout')
    return redirect('/staff/login')

# Helper functions

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
    if token_format[2] in staff_token_list[username]:
        return False
    return True

def generate_auth_token(username):
    token = f"{username}.{datetime.datetime.now() + datetime.timedelta(days=15)}.{random.randint(100000, 999999)}"
    staff_token_list[username].append(token)
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
defstaff_logijt
