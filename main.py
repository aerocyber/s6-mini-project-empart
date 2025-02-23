from flask import Flask, g, make_response, redirect, session, render_template
from admin_form import admin_routing
from hospital_form import hospital_routes
from staff_form import staff_routing
from dotenv import load_dotenv
from os import environ
from apscheduler.schedulers.background import BackgroundScheduler
from db import GeneratedPatientID, PrivateRecordDB, PublicRecordDB

load_dotenv()
SECRET_KEY = environ.get('SECRET_KEY')

def cleanup():
    pub = PublicRecordDB()
    priv = PrivateRecordDB()
    gen = GeneratedPatientID()
    pub.cleanup()
    priv.cleanup()
    gen.cleanup()

scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(cleanup, 'interval', hours=24)
scheduler.start()

app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY

app.register_blueprint(admin_routing, url_prefix='/admin')
app.register_blueprint(hospital_routes, url_prefix='/hospital')
app.register_blueprint(staff_routing, url_prefix='/staff')


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('JWT')
    resp.delete_cookie('username')
    resp.delete_cookie('role')
    if 'username' in session:
        session.pop('username')
    return resp

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.client.close()

