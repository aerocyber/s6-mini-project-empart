from pymongo import MongoClient
from os import environ
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

MONGO_DB_CONNECTION_STRING = environ.get('MONGO_DB_CONNECTION_STRING')
MONGO_DB_DATABASE = environ.get('MONGO_DB_DATABASE')
SECRET_KEY = environ.get('SECRET_KEY')

client = MongoClient(MONGO_DB_CONNECTION_STRING)
db = client[MONGO_DB_DATABASE]


class HospitalDB:
    def __init__(self):
        self.hospital_pub = db['hospital_pub']
        self.hospital_priv = db['hospital_priv']

    def add_hospital(self, hospital_id, hospital_name, hospital_location, password):
        hospital = {
            'id': hospital_id,
            'name': hospital_name,
            'location': hospital_location,
            'password': generate_password_hash(password)
        }
        hospital_pub = {
            'id': hospital_id,
            'name': hospital_name,
            'location': hospital_location
        }
        self.hospital_pub.insert_one(hospital_pub)
        self.hospital_priv.insert_one(hospital)

    def get_hospital(self, hospital_id):
        return self.hospital_pub.find_one({'id': hospital_id})
    
    def get_hospitals(self):
        return self.hospital_pub.find()
    
    def get_hospital_priv(self, hospital_id):
        return self.hospital_priv.find_one({'id': hospital_id})
    
    def remove_hospital(self, hospital_id):
        self.hospital_pub.delete_one({'id': hospital_id})
        self.hospital_priv.delete_one({'id': hospital_id})

    def update_keypair(self, hospital_id, private_key, public_key):
        # Update keypair
        self.hospital_priv.update_one({'id': hospital_id}, {'$set': {'private_key': private_key, 'public_key': public_key}})
        self.hospital_pub.update_one({'id': hospital_id}, {'$set': {'public_key': public_key}})
        
    def update_hospital(self, hospital_id, hospital_name, hospital_location, hospital_public_key, hospital_private_key):
        self.hospital_pub.update_one({'id': hospital_id}, {'$set': {'name': hospital_name, 'location': hospital_location, 'public_key': hospital_public_key}})
        self.hospital_priv.update_one({'id': hospital_id}, {'$set': {'name': hospital_name, 'location': hospital_location, 'private_key': hospital_private_key, 'public_key': hospital_public_key}})

    def get_count(self):
        return self.hospital_pub.count_documents({})
    
    

class StaffDB:
    def __init__(self):
        self.staff = db['staff']

    def add_staff(self, staff_name, staff_email, staff_password, hospital_id):
        staff = {
            'name': staff_name,
            'email': staff_email,
            'password': staff_password,
            'hospital_id': hospital_id
        }
        self.staff.insert_one(staff)

    def get_staff(self, staff_email):
        return self.staff.find_one({'email': staff_email})
    
    def get_staffs(self):
        return self.staff.find()
    
    def remove_staff(self, staff_email):
        self.staff.delete_one({'email': staff_email})
        
    def update_staff(self, staff_email, staff_password):
        self.staff.update_one({'email': staff_email}, {'$set': {'password': staff_password}})
    
    def get_count(self):
        return self.staff.count_documents({})
    
    
class PrivateRecordDB:
    def __init__(self):
        self.private_record = db['private_record']

    def add_record(self, patient_name, patient_age, patient_blood_group, patient_id, patient_medication, patient_diagnosis, patient_current_condition, patient_gender, patient_weight):
        record = {
            'name': patient_name,
            'age': patient_age,
            'blood_group': patient_blood_group,
            'gender': patient_gender,
            'id': patient_id,
            'medication': patient_medication,
            'diagnosis': patient_diagnosis,
            'current_condition': patient_current_condition,
            'weight': patient_weight
        }

        self.private_record.insert_one(record)

    def get_record(self, patient_id):
        return self.private_record.find_one({'id': patient_id})
    
    def get_records(self):
        return self.private_record.find()
    
    def remove_record(self, patient_id):
        self.private_record.delete_one({'id': patient_id})

    def update_record(self, patient_id, patient_medication, patient_diagnosis, patient_current_condition):
        self.private_record.update_one({'id': patient_id}, {'$set': {'medication': patient_medication, 'diagnosis': patient_diagnosis, 'current_condition': patient_current_condition}})

    def get_count(self):
        return self.private_record.count_documents({})
    

class PublicRecordDB:
    def __init__(self):
        self.public_record = db['public_record']

    def add_record(self, patient_id, patient_medication, patient_diagnosis, patient_current_condition):
        record = {
            'id': patient_id,
            'medication': patient_medication,
            'diagnosis': patient_diagnosis,
            'current_condition': patient_current_condition
        }

        self.public_record.insert_one(record)

    def get_record(self, patient_id):
        return self.public_record.find_one({'id': patient_id})
    
    def get_records(self):
        return self.public_record.find()
    
    def remove_record(self, patient_id):
        self.public_record.delete_one({'id': patient_id})

    def update_record(self, patient_id, patient_medication, patient_diagnosis, patient_current_condition):
        self.public_record.update_one({'id': patient_id}, {'$set': {'medication': patient_medication, 'diagnosis': patient_diagnosis, 'current_condition': patient_current_condition}})

    def get_count(self):
        return self.public_record.count_documents({})
