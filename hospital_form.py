from flask import Blueprint, request, make_response, redirect, render_template
from werkzeug.security import check_password_hash
import random
from dotenv import load_dotenv
from os import environ
import datetime
from db import HospitalDB, StaffDB
from data import generate_jwt_token, verify_jwt_token, decode_jwt_token

hospital_token_list = {}

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')
hospitalDb = HospitalDB()
staffDb = StaffDB()

hospital_routes = Blueprint('hospital_form', __name__)


@hospital_routes.route('/')
def index():
    if request.cookies.get('JWT') and verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
        h = HospitalDB()
        hospital = h.get_hospital(request.cookies.get('username'))
        return render_template('hospital_dashboard.html', hospital_name = hospital['name'], location = hospital['location'])
    if request.cookies.get('JWT'):
        return redirect('/logout')
    return redirect('/hospital/login')

@hospital_routes.route('/login', methods=['POST', 'GET'])
def hospital_login():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
                return redirect('/hospital')
            return redirect('/logout')
        
        username = request.form['email']
        password = request.form['password']
        user = hospitalDb.get_hospital(username)
        print(user)
        print(hospitalDb.check_password(username, password))
        if not user or not hospitalDb.check_password(username, password):
            return 'Invalid credentials', 403
        token = generate_jwt_token(username, password, 'hospital')
        response = make_response(redirect('/hospital'))
        response.set_cookie('JWT', token, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('username', username, expires=datetime.datetime.now() + datetime.timedelta(days=15))
        response.set_cookie('role', 'hospital', expires=datetime.datetime.now() + datetime.timedelta(days=15))
        return response
    
    if request.cookies.get('JWT'):
        if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
            resp = make_response(redirect('/hospital'))
            resp.delete_cookie('JWT')
            return resp
        return redirect('/logout')
    return render_template('hospital_login.html')

@hospital_routes.route('/add-staff', methods=['POST', 'GET'])
def add_staff():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
                staff_name = request.form['staff_name']
                staff_email = request.form['staff_email']
                staff_password = request.form['staff_password']
                h = HospitalDB()
                hospital_id = h.get_hospital(request.cookies.get('username'))['id']
                if staffDb.get_staff(staff_email):
                    return 'Staff already exists', 400
                staffDb.add_staff(staff_name, staff_email, staff_password, hospital_id)
                return redirect('/hospital')
            return redirect('/logout')
        return redirect('/hospital/login')
    return redirect('/hospital')

@hospital_routes.route('/keypair', methods=['POST', 'GET'])
def add_keypair():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
                public_key = request.form['public_key']
                private_key = request.form['private_key']
                hospital_email = request.cookies.get('username')
                hospitalDb.add_keypair(hospital_email, public_key, private_key)
                return redirect('/hospital')
            return redirect('/logout')
        return redirect('/hospital/login')
    return render_template('add_keypair.html')


@hospital_routes.route('/delete-staff', methods=['POST', 'GET'])
def remove_staff():
    if request.method == 'POST':
        if request.cookies.get('JWT'):
            if verify_jwt_token(request.cookies.get('JWT'), request.cookies.get('username'), 'hospital'):
                # staff_name = request.form['staff_name']
                staff_email = request.form['staff_email']
                # staff_password = request.form['staff_password']
                hospital_id = request.cookies.get('username')
                if not staffDb.get_staff(staff_email):
                    return 'Staff does not exists', 400
                staffDb.remove_staff(staff_email, hospital_id)
                return 'Staff deleted successfully', 201
            return redirect('/logout')
        return redirect('/hospital/login')
    return render_template('add_staff.html')