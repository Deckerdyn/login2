from app.database.db import db
from app.auth.hash import hash_password, verify_password
from bson import ObjectId

def create_user(email: str, password: str, role: str):
    hashed_password = hash_password(password)
    return db.users.insert_one({"email": email, "password": hashed_password, "role": role}).inserted_id

def get_user_by_email(email: str):
    return db.users.find_one({"email": email})

def update_user(user_id: str, updates: dict):
    return db.users.update_one({"_id": ObjectId(user_id)}, {"$set": updates})

def delete_user(user_id: str):
    return db.users.delete_one({"_id": ObjectId(user_id)})
