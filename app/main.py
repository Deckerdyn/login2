from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, HTMLResponse,JSONResponse
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
from pydantic import BaseModel
from jose import JWTError, jwt

import pytz


# Zona horaria de Chile
chile_tz = pytz.timezone("America/Santiago")
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # Define la URL para obtener el token
# Modelo para recibir el nuevo token
class TokenReplaceRequest(BaseModel):
    new_token: str
@app.post("/assign-manual-token")
async def assign_manual_token(token: str):
    try:
        # Verificar que el token sea válido
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Opcional: Verificar que el rol y otros datos son correctos
        if "role" not in decoded_token or "sub" not in decoded_token:
            raise HTTPException(status_code=400, detail="Token inválido")

        # Aquí puedes guardar este token en una base de datos, si lo deseas
        # O simplemente retornarlo para que el cliente lo use
        return JSONResponse(content={"access_token": token}, status_code=200)

    except JWTError:
        raise HTTPException(status_code=400, detail="Token inválido")
@app.post("/replace-token")
async def replace_token(request: TokenReplaceRequest):
    # Validar el formato del token si es necesario
    if not request.new_token:
        raise HTTPException(status_code=400, detail="Token no proporcionado")
    
    return {"message": "Token recibido", "access_token": request.new_token}
# Servir archivos estáticos desde una subcarpeta "static" dentro de "frontend"
app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "frontend/static")), name="static")

# Simula un almacenamiento en memoria para las consultas realizadas
query_logs = {}

# Modelo para la solicitud de creación de token
class TokenRequest(BaseModel):
    role: str  # El rol del usuario

@app.post("/create_token")
async def create_token(request: TokenRequest):
    role = request.role

    if role not in roles:
        raise HTTPException(status_code=400, detail="Rol no válido")

    # Obtiene la configuración del rol
    role_config = roles[role]

    # Calculamos la fecha de expiración según la duración del token
    expiration_time = datetime.utcnow() + timedelta(minutes=role_config["token_duration"])

    # Creamos el payload del JWT
    payload = {
        "sub": role,  # El rol del usuario como el sujeto
        "role": role,  # Guardamos el rol
        "exp": expiration_time,  # Tiempo de expiración del token
        "max_queries": role_config["max_queries"],  # Límite de consultas
        "access_schedule": role_config["access_schedule"],  # Horario de acceso
    }

    # Generamos el token JWT
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}
@app.post("/generate-token")
async def generate_token(email: str, role: str = None):
    # Busca al usuario por su email
    user = db["users"].find_one({"email": email})

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Determinar el rol a usar
    user_role = role or user.get("role", None)  # Prioriza el rol proporcionado como parámetro
    if not user_role:
        raise HTTPException(status_code=400, detail="No se especificó un rol válido para el usuario")

    # Verifica si el rol proporcionado está configurado
    role_config = roles.get(user_role)
    if not role_config:
        raise HTTPException(status_code=400, detail=f"El rol '{user_role}' no está configurado")

    # Generar el token con el rol especificado
    token = create_access_token(
        data={
            "sub": email,
            "role": user_role,
        },
        role=user_role
    )

    # Retorna el token generado
    return JSONResponse(content={"access_token": token})
def track_user_queries(user_email: str, max_queries: int):
    now = datetime.now(timezone.utc).date().isoformat()  # Formato ISO para la fecha
    user = db.users.find_one({"email": user_email})
    
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Inicializar `query_logs` si está vacío
    query_logs = user.get("query_logs", {})
    
    print(f"Tracking queries for {user_email}. Current query logs: {query_logs}")  # Debugging print
    
    if max_queries is not None:
        # Obtener el conteo actual de consultas para hoy
        current_count = query_logs.get(now, 0)
        print(f"Current query count for today: {current_count}")  # Debugging print

        if current_count >= max_queries:
            raise HTTPException(status_code=403, detail="Limite de consultas excedida")

        # Incrementar el conteo de consultas para hoy
        query_logs[now] = current_count + 1
        print(f"Updated query logs: {query_logs}")  # Debugging print
    
    # Actualizar el usuario en la base de datos
    db.users.update_one({"email": user_email}, {"$set": {"query_logs": query_logs}})






    
"""@app.get("/protected-resource")
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
    
    # Obtener el límite de consultas para el rol del usuario
    max_queries = roles.get(role, {}).get("max_queries")
    print(f"Max queries for role {role}: {max_queries}")  # Depuración
    
    # Rastrear las consultas
    track_user_queries(email, max_queries)
    
    return {"message": f"Access granted to {email}"}"""




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

@app.get("/protegido", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    with open("frontend/protegido.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate):
    # Verificar si el email ya está registrado
    existing_user = db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email ya registrado")
    
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
        "query_logs": {}  # Inicializar con un objeto vacío
    }
    
    # Insertar el usuario en la base de datos
    user_id = db.users.insert_one(user_data).inserted_id
    
    return {"id": str(user_id), "email": user.email, "role": user.role}



@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    # Buscar al usuario por correo electrónico en la base de datos
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Credenciales inválidas")
    
    # Verificar la contraseña
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Credenciales inválidas")
    
    # Revisar si el usuario ya tiene un token válido almacenado
    stored_token = user.get("access_token")
    if stored_token:
        try:
            payload = verify_token(stored_token)  # Verificar si el token es válido
            # Comprobar si el token ha expirado
            if datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return {"access_token": stored_token, "token_type": "bearer"}
        except:
            # Si el token no es válido o ha expirado, continuamos para generar uno nuevo
            pass




@app.get("/protected")
def protected_route(token: str = Depends(verify_token)):
    if not token:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    email = token.get("sub")
    role = token.get("role")
    exp = token.get("exp")
    iat = token.get("iat")

    if not email or not role or not exp:
        raise HTTPException(status_code=401, detail="Datos del token inválidos")

    # Obtener datos del rol
    role_data = roles.get(role)
    if not role_data:
        raise HTTPException(status_code=403, detail="Rol no encontrado")

    max_queries = role_data.get("max_queries")
    token_duration = role_data.get("token_duration")
    access_schedule = role_data.get("access_schedule")

    #if max_queries is None:
    #    raise HTTPException(status_code=403, detail="Query limit not defined for this role")

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
        raise HTTPException(status_code=401, detail="Token expirado")

    # Verificación del horario de acceso
    if access_schedule:
        current_hour = now_chile.hour
        if not (access_schedule["start"] <= current_hour < access_schedule["end"]):
            raise HTTPException(status_code=403, detail="Acceso no permitido fuera del horario previsto")

    # Rastrear las consultas del usuario
    track_user_queries(email, max_queries)

    return {"message": f"Access granted to {email}", "role": role}






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
