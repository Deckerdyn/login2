from sshtunnel import SSHTunnelForwarder
from pymongo import MongoClient
from decouple import config
from pymongo.database import Database

# Cargar variables desde .env
SSH_HOST = config("SSH_HOST")                  # Ejemplo: 10.10.8.60
SSH_PORT = int(config("SSH_PORT", default=22))
SSH_USER = config("SSH_USER")
SSH_PASSWORD = config("SSH_PASSWORD")

REMOTE_MONGO_HOST = config("REMOTE_MONGO_HOST", default="127.0.0.1")
REMOTE_MONGO_PORT = int(config("REMOTE_MONGO_PORT", default=27017))
DB_NAME = config("DB_NAME", default="micro_algas")

# Iniciar el túnel SSH de forma global
tunnel = SSHTunnelForwarder(
    (SSH_HOST, SSH_PORT),
    ssh_username=SSH_USER,
    ssh_password=SSH_PASSWORD,
    remote_bind_address=(REMOTE_MONGO_HOST, REMOTE_MONGO_PORT)
)
tunnel.start()  # El túnel se mantiene activo hasta que se llame a tunnel.stop()

# Construir la cadena de conexión usando el puerto local asignado por el túnel
connection_string = f"mongodb://127.0.0.1:{tunnel.local_bind_port}/?directConnection=true"
client = MongoClient(connection_string)
db = client[DB_NAME]

# Seleccionar las colecciones
users_collection = db["users"]
meditions_collection = db["medicions"]

# Verificar la conexión
try:
    client.admin.command('ping')
    print("Conexión a MongoDB exitosa en la base de datos:", DB_NAME)
except Exception as e:
    print("Error al conectar con MongoDB:", e)

# Opcional: podrías definir una función para cerrar el túnel al detener la aplicación
def shutdown_tunnel():
    tunnel.stop()
