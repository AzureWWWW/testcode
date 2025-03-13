from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt

app = FastAPI()

# Database setup
DATABASE_URL = "sqlite:///./hospital.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Authentication
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")  # Added role for user/administrator
    appointments = relationship("Appointment", back_populates="user")

# Doctor model
class Doctor(Base):
    __tablename__ = "doctors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    specialization = Column(String)
    appointments = relationship("Appointment", back_populates="doctor")

# Appointment model
class Appointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    doctor_id = Column(Integer, ForeignKey("doctors.id"))
    date_time = Column(DateTime, nullable=False)
    description = Column(String, nullable=False)
    user = relationship("User", back_populates="appointments")
    doctor = relationship("Doctor", back_populates="appointments")

Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class AppointmentCreate(BaseModel):
    date_time: datetime
    description: str
    doctor_id: int

class PasswordReset(BaseModel):
    email: str
    new_password: str

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper function to create JWT token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Helper function to get the current user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Hash password using bcrypt
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Verify password using bcrypt
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# Admin role check
def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return current_user

# redirect root path
@app.get("/")
async def redirect_root_to_docs():
    return RedirectResponse("/docs")

# User registration
@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existed_user = db.query(User).filter(User.username == user.username).first()
    if existed_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = hash_password(user.password)
    existed_email = db.query(User).filter(User.email == user.email).first()
    if existed_email:
        raise HTTPException(status_code=400, detail="This email has already been used")
    hashed_password = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

# User login and JWT token generation
@app.post("/login/", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Password reset
@app.post("/reset-password/")
def reset_password(data: PasswordReset, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    hashed_password = hash_password(data.new_password)
    user.hashed_password = hashed_password
    db.commit()
    return {"message": "Password reset successfully"}

# Get all doctors (No authentication required)
@app.get("/doctors")
def get_all_doctors(db: Session = Depends(get_db)):
    doctors = db.query(Doctor).all()
    return doctors

# Book an appointment (Requires Authentication)
@app.post("/appointments/")
def book_appointment(appointment: AppointmentCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_appointment = Appointment(user_id=user.id, doctor_id=appointment.doctor_id, date_time=appointment.date_time, description=appointment.description)
    db.add(new_appointment)
    db.commit()
    db.refresh(new_appointment)
    return {"message": "Appointment booked successfully", "appointment": appointment}

# Admin: Get all users, doctors and appointments
@app.get("/admin/data/")
def get_all_database(admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    appointments = db.query(Appointment).all()
    doctors = db.query(Doctor).all()
    return users, appointments, doctors

# Admin: Delete a user
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    related_appointment = db.query(Appointment).filter(Appointment.user_id == user_id).all()
    for appointment in related_appointment:
        db.delete(appointment)
    db.delete(user)
    db.commit()
    return {"message": "User and its appointments deleted successfully"}

# Admin: Delete an appointment
@app.delete("/admin/appointments/{appointment_id}")
def delete_appointment(appointment_id: int, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    db.delete(appointment)
    db.commit()
    return {"message": "Appointment deleted successfully"}

# Admin: delete a doctor
@app.delete("/admin/doctors/{doctor_id}")
def delete_doctor(doctor_id: int, _: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    db.delete(doctor)
    db.commit()
    return {"message": "Doctor deleted"}
