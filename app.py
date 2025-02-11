from flask import Flask, g, make_response, redirect
from staff_api import api
from admin_api import admin
from hospital_login import hospital
from admin_form import admin_routing
from hospital_form import hospital_routes
from staff_form import staff_routing


app = Flask(__name__)
app.register_blueprint(api, url_prefix='/api/staff')
app.register_blueprint(admin, url_prefix='/api/admin')
app.register_blueprint(hospital, url_prefix='/api/hospital')
app.register_blueprint(admin_routing, url_prefix='/admin')
app.register_blueprint(hospital_routes, url_prefix='/hospital')
app.register_blueprint(staff_routing, url_prefix='/staff')

@app.route('/')
def home():
    return 'Welcome to the EmPaRT!'

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('JWT')
    return resp

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.client.close()