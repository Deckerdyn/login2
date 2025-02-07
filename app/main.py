from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Form
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from app.database.db import db  
from app.models.user import UserCreate, UserResponse  
from app.auth.hash import hash_password, verify_password  
from app.auth.jwt import create_access_token, verify_token  
import os
from bson import ObjectId
from app.database.db import users_collection  
from datetime import datetime, timedelta, timezone
import jwt
from app.auth.jwt import SECRET_KEY, ALGORITHM  
from app.auth.roles import roles  
import pytz
from decouple import config
import secrets 
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware  # Importar correctamente
from starlette.responses import Response

# Zona horaria de Chile
chile_tz = pytz.timezone("America/Santiago")
app = FastAPI()


# Definir el middleware CSP
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        
        # Deshabilitar CSP solo para Swagger UI
        if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc"):
            return response

        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' https://api.open-meteo.com; "
            "object-src 'none'; "
            "frame-src 'none'; "
            "base-uri 'self';"
        )
        return response

# Añadir el middleware a la aplicación FastAPI
app.add_middleware(CSPMiddleware)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # Define la URL para obtener el token

# Servir archivos estáticos desde una subcarpeta "static" dentro de "frontend"
app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "frontend/static")), name="static")

# Simula un almacenamiento en memoria para las consultas realizadas
query_logs = {}

# Middleware CORS (necesario para permitir frontend en otro dominio si aplica)
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:8000"],  
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
# Diccionario en memoria para registrar intentos fallidos
failed_login_attempts = {}

MAX_ATTEMPTS = 3  # Máximo de intentos antes de bloquear
BLOCK_TIME = timedelta(minutes=1)  # Tiempo de bloqueo

# 🔹 Generar un token CSRF seguro
def generate_csrf_token():
    return secrets.token_urlsafe(32)

@app.get("/csrf-token")
async def get_csrf_token(request: Request):
    # Verificar si el usuario está autenticado
    if not request.cookies.get("access_token"):  # Verificar que el usuario esté autenticado
        raise HTTPException(status_code=401, detail="No autenticado")

    # Si ya hay un CSRF Token en las cookies, no lo generes nuevamente
    csrf_token = request.cookies.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_hex(16)  # Genera un CSRF Token si no hay uno

    response = JSONResponse({"csrf_token": csrf_token})
    # Establecer el token en la cookie si no existe
    response.set_cookie("csrf_token", csrf_token, httponly=True, secure=True, samesite="Strict", max_age=timedelta(hours=24))
    return response


def track_user_queries(user_email: str, max_queries: int):
    now = datetime.now(timezone.utc).date().isoformat()  # Formato ISO para la fecha
    user = db.users.find_one({"email": user_email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not foundd")
    
    # Inicializar `query_logs` si está vacío
    query_logs = user.get("query_logs", {})
    
    print(f"Consultas de seguimiento para {user_email}. Registros de consultas actuales: {query_logs}")  # Debugging print
    
    if max_queries is not None:
        # Obtener el conteo actual de consultas para hoy
        current_count = query_logs.get(now, 0)
        print(f"Current query count for today: {current_count}")  # Debugging print

        if current_count >= max_queries:
            raise HTTPException(status_code=403, detail="Limite de consultas excedido")

        # Incrementar el conteo de consultas para hoy
        query_logs[now] = current_count + 1
        print(f"Updated query logs: {query_logs}")  # Debugging print
    
    # Actualizar el usuario en la base de datos
    db.users.update_one({"email": user_email}, {"$set": {"query_logs": query_logs}})



# @app.post("/replace-token/{new_token}")
# async def replace_token(new_token: str, request: Request, response: Response):
#     # Obtener el token actual de la cookie HttpOnly
#     current_token = request.cookies.get("access_token")
    
#     if not current_token:
#         raise HTTPException(status_code=400, detail="No se encontró ningún token en las cookies.")
    
#     # Verificar el token actual
#     try:
#         decoded_token = verify_token(current_token)  # Asumiendo que esta función decodifica y valida el token
#     except Exception as e:
#         raise HTTPException(status_code=401, detail="Token no válido")

#     # Verificar el nuevo token (si es necesario)
#     try:
#         decoded_new_token = verify_token(new_token)  # Opcional, puedes validar el nuevo token si es necesario
#     except Exception as e:
#         raise HTTPException(status_code=400, detail="Nuevo token no válido.")
    
#     # Establecer el nuevo token en la cookie HttpOnly
#     response.set_cookie(
#         key="access_token",
#         value=new_token,
#         httponly=True,
#         max_age=timedelta(hours=24),  # Ajusta la duración según sea necesario
#         secure=False  # Cambiar a True en producción si usas HTTPS
#     )

#     return {"access_token": new_token, "message": "Token reemplazado exitosamente"}




    
@app.get("/protected-resource")
def protected_resource(token: str = Depends(oauth2_scheme)):
    print("Received request at /protected-resource")  # Depuración
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")  # Depuración
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha caducado")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail="Token no válido")
    
    role = payload.get("role")
    email = payload.get("sub")
    
    print(f"Role: {role}, Email: {email}")  # Depuración

    if not role or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")
    
    
    
    return {"message": f"Acceso concedido a {email}"}


@app.get("/protegido", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    with open("frontend/protegido.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

@app.get("/")
async def get_index():
    # Asegúrate de usar UTF-8 al leer el archivo
    with open("frontend/index.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

# Función para verificar el rol del usuario
def role_required(required_role: str):
    def role_checker(token: dict = Depends(verify_token)):
        if token["role"] != required_role:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return token
    return role_checker

"""@app.get("/admin")
def admin_route(token: str):
    try:
        payload = verify_token(token)
        
        # Validar que el token contenga el campo 'role'
        role = payload.get("role")
        if not role:
            raise HTTPException(status_code=403, detail="Role not found in token")
        
        # Verificar si el rol es 'admin'
        if role != "admin":
            raise HTTPException(status_code=403, detail="Access denied")
        
        return {"message": "Welcome Admin"}
    
    except HTTPException as e:
        raise e  # Excepciones controladas
    
    except Exception as e:
        print(f"Error en /admin: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")



@app.get("/user")
def get_user_data(token: dict = Depends(role_required("usuario"))):
    return {"message": "Welcome, User!"}

@app.get("/temporal")
def get_temporal_data(token: dict = Depends(role_required("temporal"))):
    return {"message": "Welcome, Temporal User!"}"""
    
# Ruta para el dashboard
@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    with open("frontend/dashboard.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate):
    # Verificar si el email ya está registrado
    existing_user = db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Correo electrónico ya registrado")
    
    # Hash de la contraseña
    hashed_password = hash_password(user.password)
    
    # Asignar un rol por defecto si no se especifica
    if not user.role:
        user.role = 'usuario'  # Rol predeterminado para nuevos usuarios
    
    # Crear el documento del usuario con el campo `query_logs` inicializado
    user_data = {
        "email": user.email,
        "password": hashed_password,
        "role": user.role,
        "query_logs": {},  # Inicializar log de consultas
        #"active_token": None  # Campo para almacenar el token activoampo para almacenar el token activo
    }
    
    # Insertar el usuario en la base de datos
    user_id = db.users.insert_one(user_data).inserted_id
    
    return {"id": str(user_id), "email": user.email, "role": user.role}



# 🔹 Agregar CSRF Token al iniciar sesión
@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), response: Response = None):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Credenciales no válidas")

    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Credenciales no válidas")

    role = user.get("role", "temporary_user")

    # 🔸 Generar el token de acceso
    access_token = create_access_token(data={"sub": user["email"], "role": role}, role=role)

    # 🔹 Generar el token CSRF y almacenarlo en una cookie segura
    csrf_token = generate_csrf_token()
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  
        max_age=timedelta(hours=24),
        secure=False  # Cambiar a True en producción
    )

    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # El frontend debe poder leerlo
        samesite="Strict",
        secure=False  # Cambiar a True en producción
    )

    return {"csrf_token": csrf_token, "message": "Inicio de sesión exitoso"}


# 🔹 Middleware para validar el CSRF Token en cada solicitud POST, PUT, DELETE
async def verify_csrf_token(request: Request, csrf_token: str = Header(None)):
    stored_csrf_token = request.cookies.get("csrf_token")
    
    if not stored_csrf_token or stored_csrf_token != csrf_token:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

# 🔹 Proteger las rutas que modifican datos
@app.post("/protected-action", dependencies=[Depends(verify_csrf_token)])
async def protected_action():
    return {"message": "Token CSRF validado exitosamente"}




@app.post("/generate-token")
async def generate_token(email: str, role: str):
    # Verifica si el rol proporcionado existe en la configuración
    role_config = roles.get(role)
    if not role_config:
        raise HTTPException(status_code=400, detail=f"El rol '{role}' no está configurado")
    
    # Busca al usuario por su correo electrónico
    user = db["users"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Genera el token manualmente
    token = create_access_token(
        data={"sub": email, "role": role},
        role=role
    )

    # Retorna el token generado
    return JSONResponse(content={"access_token": token, "token_type": "bearer"})




@app.get("/protected")
async def protected_route(request: Request):
    # Obtener el CSRF token desde las cookies HTTPOnly
    csrf_token_from_cookie = request.cookies.get("csrf_token")

    if not csrf_token_from_cookie:
        raise HTTPException(status_code=401, detail="Falta el token CSRF")

    # Obtener el CSRF token enviado en la cabecera
    csrf_token_from_header = request.headers.get("X-CSRF-Token")

    if not csrf_token_from_header:
        raise HTTPException(status_code=401, detail="Falta el token CSRF en la solicitud")

    # Comparar ambos tokens (del cookie y del header)
    if csrf_token_from_cookie != csrf_token_from_header:
        raise HTTPException(status_code=403, detail="Token CSRF no válido")

    # Obtener los datos del usuario del token de la cookie de sesión (no es necesario verificar el JWT aquí)
    token_from_cookie = request.cookies.get("access_token")

    if not token_from_cookie:
        raise HTTPException(status_code=401, detail="Falta el token de acceso")

    # Verificar el token usando la función 'verify_token'
    try:
        token = verify_token(token_from_cookie)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Token no válido")

    # Obtener los datos del token
    email = token.get("sub")
    role = token.get("role")
    exp = token.get("exp")
    iat = token.get("iat")

    if not email or not role or not exp:
        raise HTTPException(status_code=401, detail="Datos de token no válidos")

    # Obtener los datos del rol
    role_data = roles.get(role)
    if not role_data:
        raise HTTPException(status_code=403, detail="Rol no encontrado")

    max_queries = role_data.get("max_queries")
    token_duration = role_data.get("token_duration")
    access_schedule = role_data.get("access_schedule")

    # Hora actual en la zona horaria de Chile
    now_chile = datetime.now(chile_tz)
    print(f"Hora actual en Chile: {now_chile}")

    # Verificación de la duración del token
    if iat is not None and token_duration is not None:
        issued_at = datetime.fromtimestamp(iat, timezone.utc).astimezone(chile_tz)
        token_lifetime = timedelta(minutes=token_duration)
        if now_chile > issued_at + token_lifetime:
            raise HTTPException(status_code=401, detail="Se superó la duración del token")
    else:
        print("Warning: 'iat' or 'token_duration' is missing in the token or role configuration")

    # Verificación de la expiración del token
    token_expiration = datetime.fromtimestamp(exp, timezone.utc).astimezone(chile_tz)
    if now_chile > token_expiration:
        raise HTTPException(status_code=401, detail="El token ha caducado")

    # Verificación del horario de acceso
    if access_schedule:
        current_hour = now_chile.hour
        if not (access_schedule["start"] <= current_hour < access_schedule["end"]):
            raise HTTPException(status_code=403, detail="Acceso no permitido fuera del horario previsto")

    # Obtener el límite de consultas para el rol del usuario
    print(f"Consultas máximas para el rol {role}: {max_queries}")  # Depuración
    
    # Rastrear las consultas
    track_user_queries(email, max_queries)

    return {"message": f"Acceso concedido a {email}", "role": role}


@app.post("/logout")
async def logout(response: Response):
    # Eliminar la cookie del token HTTPOnly
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    
    return {"message": "Cerró sesión exitosamente"}



@app.put("/update_user/{user_id}", response_model=UserResponse)
def update_user(user_id: str, user: UserCreate):
    db_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    updated_data = {}
    if user.email:
        updated_data["email"] = user.email
    if user.password:
        updated_data["password"] = hash_password(user.password)
    
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": updated_data})
    
    return {"id": user_id, "email": user.email}

@app.delete("/delete_user/{user_id}", response_model=UserResponse)
def delete_user(user_id: str):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    db.users.delete_one({"_id": ObjectId(user_id)})
    return {"id": user_id, "email": user["email"]}
