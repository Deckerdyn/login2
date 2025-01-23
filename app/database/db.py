from pymongo import MongoClient
from decouple import config

# Cargar variables desde .env
MONGO_URI = config("MONGO_URI", default="mongodb://localhost:27017")
DB_NAME = config("DB_NAME", default="fastapi_db")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Selecciona la colección "users" (cambia el nombre si tu colección tiene otro nombre)
users_collection = db["users"]
