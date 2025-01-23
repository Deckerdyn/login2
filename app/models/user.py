from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str  # Agregamos el campo 'role' para el rol del usuario
    
class UserResponse(BaseModel):
    id: str
    email: EmailStr
    role: str  # Agregamos el campo 'role' para el rol del usuario
    
class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str