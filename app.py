from flask import Flask, g
from staff_api import api
from admin_api import admin
from hospital_login import hospital
from admin_form import admin_routing
from hospital_form import hospital_routing

app = Flask(__name__)
app.register_blueprint(api, url_prefix='/api/staff')
app.register_blueprint(admin, url_prefix='/api/admin')
app.register_blueprint(hospital, url_prefix='/api/hospital')
app.register_blueprint(admin_routing, url_prefix='/admin')
app.register_blueprint(hospital_routing, url_prefix='/hospital')

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.client.close()