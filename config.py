# from pydantic_settings import BaseSettings

# class Settings(BaseSettings):
#     # Configuración de la base de datos
#     MONGO_URI: str
#     DB_NAME: str

#     # Variables de conexión SSH y MongoDB
#     SSH_HOST: str
#     SSH_PORT: int = 22
#     SSH_USER: str
#     SSH_PASSWORD: str
#     REMOTE_MONGO_HOST: str
#     REMOTE_MONGO_PORT: int = 27017

#     # Credenciales API
#     CLIENT_ID: str
#     CLIENT_SECRET: str

#     class Config:
#         env_file = ".env"  # Especifica el archivo de entorno

# settings = Settings()
