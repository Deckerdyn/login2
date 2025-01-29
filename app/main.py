from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from app.database.db import db  # Corregido
from app.models.user import UserCreate, UserResponse, Token, LoginRequest  # Corregido
from app.auth.hash import hash_password, verify_password  # Corregido
from app.auth.jwt import create_access_token, verify_token  # Corregido
from fastapi import Form
import os
from bson import ObjectId
from app.database.db import users_collection  
from datetime import datetime, timedelta, timezone
import jwt
from app.auth.jwt import SECRET_KEY, ALGORITHM  # Ajusta la ruta si es necesario
from app.auth.roles import roles  

import pytz

# Zona horaria de Chile
chile_tz = pytz.timezone("America/Santiago")
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # Define la URL para obtener el token

# Servir archivos estáticos desde una subcarpeta "static" dentro de "frontend"
app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "frontend/static")), name="static")

# Simula un almacenamiento en memoria para las consultas realizadas
query_logs = {}

from app.auth.roles import roles

def track_user_queries(user_email: str, max_queries: int):
    now = datetime.now(timezone.utc).date().isoformat()  # Formato ISO para la fecha
    user = db.users.find_one({"email": user_email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not foundd")
    
    # Inicializar `query_logs` si está vacío
    query_logs = user.get("query_logs", {})
    
    print(f"Tracking queries for {user_email}. Current query logs: {query_logs}")  # Debugging print
    
    if max_queries is not None:
        # Obtener el conteo actual de consultas para hoy
        current_count = query_logs.get(now, 0)
        print(f"Current query count for today: {current_count}")  # Debugging print

        if current_count >= max_queries:
            raise HTTPException(status_code=403, detail="Query limit exceeded")

        # Incrementar el conteo de consultas para hoy
        query_logs[now] = current_count + 1
        print(f"Updated query logs: {query_logs}")  # Debugging print
    
    # Actualizar el usuario en la base de datos
    db.users.update_one({"email": user_email}, {"$set": {"query_logs": query_logs}})



@app.post("/replace-token/{new_token}")
async def replace_token(new_token: str, request: Request, response: Response):
    # Obtener el token actual de la cookie HttpOnly
    current_token = request.cookies.get("access_token")
    
    if not current_token:
        raise HTTPException(status_code=400, detail="No token found in cookies.")
    
    # Verificar el token actual
    try:
        decoded_token = verify_token(current_token)  # Asumiendo que esta función decodifica y valida el token
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token.")

    # Verificar el nuevo token (si es necesario)
    try:
        decoded_new_token = verify_token(new_token)  # Opcional, puedes validar el nuevo token si es necesario
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid new token.")
    
    # Establecer el nuevo token en la cookie HttpOnly
    response.set_cookie(
        key="access_token",
        value=new_token,
        httponly=True,
        max_age=timedelta(hours=24),  # Ajusta la duración según sea necesario
        secure=False  # Cambiar a True en producción si usas HTTPS
    )

    return {"access_token": new_token, "message": "Token replaced successfully"}




    
@app.get("/protected-resource")
def protected_resource(token: str = Depends(oauth2_scheme)):
    print("Received request at /protected-resource")  # Depuración
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")  # Depuración
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    role = payload.get("role")
    email = payload.get("sub")
    
    print(f"Role: {role}, Email: {email}")  # Depuración

    if not role or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    
    
    return {"message": f"Access granted to {email}"}


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
            raise HTTPException(status_code=403, detail="Insufficient permissions")
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
        raise HTTPException(status_code=400, detail="Email already registered")
    
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
        "active_token": None  # Campo para almacenar el token activoampo para almacenar el token activo
    }
    
    # Insertar el usuario en la base de datos
    user_id = db.users.insert_one(user_data).inserted_id
    
    return {"id": str(user_id), "email": user.email, "role": user.role}



@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), response: Response = None):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    role = user.get("role", "temporary_user")  # Predeterminado a "temporary_user" si no tiene rol

    # Eliminar el token antiguo de la cookie (si existe)
    response.delete_cookie("access_token")

    # Generar el nuevo token
    access_token = create_access_token(data={"sub": user["email"], "role": role}, role=role)

    # Establecer el nuevo token en la cookie como HTTPOnly
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  # Proteger la cookie
        max_age=timedelta(hours=24),  # Ajusta la duración según sea necesario
        secure=False  # Cambiar a True en producción si usas HTTPS
    )

    return {"access_token": access_token, "token_type": "bearer", "message": "Nuevo token generado"}




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
    # Obtener el token desde las cookies HTTPOnly
    token_from_cookie = request.cookies.get("access_token")

    if not token_from_cookie:
        raise HTTPException(status_code=401, detail="Token is missing")

    # Verificar el token usando la función 'verify_token'
    try:
        token = verify_token(token_from_cookie)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Obtener los datos del token
    email = token.get("sub")
    role = token.get("role")
    exp = token.get("exp")
    iat = token.get("iat")

    if not email or not role or not exp:
        raise HTTPException(status_code=401, detail="Invalid token data")

    # Obtener los datos del rol
    role_data = roles.get(role)
    if not role_data:
        raise HTTPException(status_code=403, detail="Role not found")

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
            raise HTTPException(status_code=401, detail="Token duration exceeded")
    else:
        print("Warning: 'iat' or 'token_duration' is missing in the token or role configuration")

    # Verificación de la expiración del token
    token_expiration = datetime.fromtimestamp(exp, timezone.utc).astimezone(chile_tz)
    if now_chile > token_expiration:
        raise HTTPException(status_code=401, detail="Token has expired")

    # Verificación del horario de acceso
    if access_schedule:
        current_hour = now_chile.hour
        if not (access_schedule["start"] <= current_hour < access_schedule["end"]):
            raise HTTPException(status_code=403, detail="Access not allowed outside of scheduled hours")
    # Obtener el límite de consultas para el rol del usuario
    max_queries = roles.get(role, {}).get("max_queries")
    print(f"Max queries for role {role}: {max_queries}")  # Depuración
    
    # Rastrear las consultas
    track_user_queries(email, max_queries)
    # Rastrear las consultas del usuario


    return {"message": f"Access granted to {email}", "role": role}

@app.post("/logout")
async def logout(response: Response):
    # Eliminar la cookie del token HTTPOnly
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}



@app.put("/update_user/{user_id}", response_model=UserResponse)
def update_user(user_id: str, user: UserCreate):
    db_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
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
        raise HTTPException(status_code=404, detail="User not found")
    
    db.users.delete_one({"_id": ObjectId(user_id)})
    return {"id": user_id, "email": user["email"]}
