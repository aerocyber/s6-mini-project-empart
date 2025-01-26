from flask import Flask, render_template, request, redirect, make_response, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from os import getenv
from pymongo import MongoClient
import jwt
import datetime

load_dotenv()

# Database type: MongoDB
# Mongo Configurations goes below.

MONGO_DB_CONNECTION_STRING = getenv("MONGO_DB_CONNECTION_STRING")
MONGO_DB_COLLECTION = getenv("MONGO_DB_COLLECTION")
SECRET_KEY = getenv("SECRET_KEY")
if MONGO_DB_CONNECTION_STRING is None:
    print("[ERROR]: The connection string MONGO_DB_CONNECTION_STRING is not set")
    exit(1)

if MONGO_DB_COLLECTION is None:
    print("[ERROR]: The collection name MONGO_DB_COLLECTION is not set")
    exit(1)

if SECRET_KEY is None:
    print("[WARNING]: The SECRET_KEY variable is currently unset. Set it when deploying in production.")
    print("[WARNING]: Development key used for SECRET_KEY. DO NOT PROCEED IN PRODUCTION")
    c = input("Continue? [Y/y]    ")
    if not (c.lower() == 'y'):
        exit(0)
    SECRET_KEY = "development_version_key_used"

client = MongoClient(MONGO_DB_CONNECTION_STRING)
collection = client[MONGO_DB_COLLECTION]


app = Flask(__name__)

@app.route('/')
def home_route():
    if jwt_verify(request.cookies.get('userlogin')):
        return render_template('dashboard-nurse.html') # TODO: Use roles to change dashboard views
    return render_template('index.html')

@app.route('/about')
def about_route():
    return "About Page" # TODO: Replace with render_template


@app.route('/signin', methods=['GET', 'POST'])
def login_route():
    _u = request.cookies.get("userlogin")
    if _u:
        if jwt_verify(_u):
            return redirect(url_for('/'))
    if request.method == 'POST':
        # Login Logic
        username = request.form['email']
        if username is None or username == "":
            return "Username is required", 403
        record = collection["authdb"].find_one({"email": username.lower()})["password"]
        password = check_password_hash(record, request.form['password'])

        if not password:
            return "Invalid credentials", 403

        # flash("Login successful!")
        ulogin = jwt_forge(username)
        print(ulogin) # FIXME: Remove this line

        # resp = make_response(redirect('/')) # TODO: Make it dashboard
        resp = make_response(redirect(url_for('home_route')))
        resp.set_cookie('userlogin', ulogin, expires=datetime.datetime.now() + datetime.timedelta(days=30))

        return resp

    return render_template("login.html")


@app.route('/signup', methods=['GET', 'POST'])
def register_route():
    if request.method == "POST":
        username = request.form["email"]
        password = request.form["password"]
        # role = request.form["user-role"] # 
        # TODO: Validation
        pswd = generate_password_hash(password)
        records = collection["authdb"].find()
        for i in records:
            if i["email"] == username:
                return "This email has already been registered", 403

        # collection["authdb"].insert_one({"email": username.lower(), "password": pswd, "role": role})
        collection["authdb"].insert_one({"email": username.lower(), "password": pswd})
    return render_template("signup.html")

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('userlogin')
    return resp

def jwt_forge(uname):
    payload = {"User": uname}
    token = jwt.encode(
        payload=payload,
        key=SECRET_KEY,
        algorithm="HS256",
    )
    
    return token

def jwt_verify(token):
    try:
        payload = jwt.decode(
            jwt=token,
            key=SECRET_KEY,
            algorithms=["HS256"]
        )
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    return True