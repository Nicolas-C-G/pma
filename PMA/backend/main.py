from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from typing import List

from database import Base, engine, get_db
from models import User
from auth import hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM

Base.metadata.create_all(bind=engine)

app = FastAPI()

# allow your React app

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

class RegisterIn(BaseModel):
    email: EmailStr
    username: str
    password: str

class Get_all_users(BaseModel):
    id: int
    email: str
    username: str
    password_hash: str

    class Config:
        from_attributes = True

class LoginIn(BaseModel):
    username_or_email: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

def get_current_user(token: str, db: Session) -> User:
    try:
        playload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = playload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.post("/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    
    user = User(
        email=data.email,
        username=data.username,
        password_hash=hash_password(data.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True, "user_id": user.id}

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = (
        db.query(User).filter((User.username == data.username_or_email) | (User.email == data.username_or_email)).first()
    )
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token}

@app.get("/dashboard")
def dashboard(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    
    token = authorization.replace("Bearer ", "").strip()
    user = get_current_user(token, db)
    return {"id": user.id, "email": user.email, "username": user.username}

@app.get("/db/all", response_model=List[Get_all_users])
def all(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users