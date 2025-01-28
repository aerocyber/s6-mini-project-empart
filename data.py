from flask import g
from pymongo import MongoClient
from dotenv import load_dotenv
from os import environ

load_dotenv()
MONGO_DB_CONNECTION_STRING = environ.get('MONGO_DB_CONNECTION_STRING')
MONGO_DB_COLLECTION = environ.get('MONGO_DB_COLLECTION')
SECRET_KEY = environ.get('SECRET_KEY')

if not MONGO_DB_CONNECTION_STRING:
    raise ValueError('No MONGO_DB_CONNECTION_STRING set for Flask application')
if not MONGO_DB_COLLECTION:
    raise ValueError('No MONGO_DB_COLLECTION set for Flask application')
if not SECRET_KEY:
    raise ValueError('No SECRET_KEY set for Flask application')


def connect_to_database():
    client = MongoClient(MONGO_DB_CONNECTION_STRING)
    return client[MONGO_DB_COLLECTION]

def get_db():
    if 'db' not in g:
        g.db = connect_to_database()
    return g.db
