from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from app.models.user import UserCreate
from app.auth.hash import verify_password
from typing import Optional
from fastapi import HTTPException
from app.database.db import db
from app.auth.roles import roles

SECRET_KEY = "your_secret_key"  # Cambia por tu clave secreta
ALGORITHM = "HS256"

def create_access_token(data: dict, role: str):
    to_encode = data.copy()
    max_queries = roles.get(role, {}).get("max_queries", None)  # Obtener el límite de consultas del rol
    to_encode.update({"role": role, "max_queries": max_queries})
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})  # Añadir el campo iat
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt





def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # Esto incluirá el rol
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
