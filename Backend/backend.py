# Habit Tracker Backend (FastAPI + SQLite)
# Project structure shown below, followed by files you'll need.

"""
Project layout (single-file example here for simplicity):

habit-tracker-backend/
├─ README.md
├─ requirements.txt
├─ .env.example
└─ main.py         # contains entire backend (models, auth, routes, DB)

This single-file app uses:
- FastAPI
- SQLModel (simple ORM built on SQLAlchemy)
- SQLite (local file db)
- python-jose for JWTs
- passlib for password hashing

Run:
1. python -m venv .venv
2. source .venv/bin/activate   # or .venv\Scripts\activate on Windows
3. pip install -r requirements.txt
4. uvicorn main:app --reload

Endpoints (high-level):
- POST /register -> create user
- POST /login -> get JWT token
- GET /habits -> list current user's habits
- POST /habits -> create habit
- GET /habits/{id} -> get single habit
- PATCH /habits/{id} -> update habit
- DELETE /habits/{id} -> delete habit
- POST /habits/{id}/complete -> mark habit as completed for a date
- GET /habits/{id}/log -> get completion log
- GET /stats -> simple stats: streaks / weekly counts

Copy the single file `main.py` below into your project folder.
"""

# ------------------------- main.py -------------------------
from datetime import datetime, timedelta, date
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlmodel import Field, SQLModel, create_engine, Session, select
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import os

# ----- Configuration -----
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./habit_tracker.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ----- DB setup -----
engine = create_engine(DATABASE_URL, echo=False)

# ----- Models -----
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str

class Habit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    title: str
    description: Optional[str] = None
    frequency: Optional[str] = Field(default="daily")  # daily/weekly/custom
    created_at: datetime = Field(default_factory=datetime.utcnow)

class HabitLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    habit_id: int = Field(index=True)
    user_id: int = Field(index=True)
    date: date = Field(default_factory=date.today)
    note: Optional[str] = None

# ----- Pydantic schemas -----
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class HabitCreate(BaseModel):
    title: str
    description: Optional[str] = None
    frequency: Optional[str] = "daily"

class HabitRead(BaseModel):
    id: int
    title: str
    description: Optional[str]
    frequency: str
    created_at: datetime

class HabitLogCreate(BaseModel):
    date: Optional[date] = None
    note: Optional[str] = None

# ----- Security -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        if user is None:
            raise credentials_exception
        return user

# ----- App -----
app = FastAPI(title="Habit Tracker API")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ----- Auth endpoints -----
@app.post("/register", status_code=201)
def register(user_in: UserCreate):
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.username == user_in.username)).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered")
        user = User(username=user_in.username, hashed_password=get_password_hash(user_in.password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"id": user.id, "username": user.username}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == form_data.username)).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

# ----- Habit endpoints -----
@app.post("/habits", response_model=HabitRead)
def create_habit(habit_in: HabitCreate, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habit = Habit(user_id=current_user.id, title=habit_in.title, description=habit_in.description, frequency=habit_in.frequency)
        session.add(habit)
        session.commit()
        session.refresh(habit)
        return HabitRead(id=habit.id, title=habit.title, description=habit.description, frequency=habit.frequency, created_at=habit.created_at)

@app.get("/habits", response_model=List[HabitRead])
def list_habits(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
        return [HabitRead(id=h.id, title=h.title, description=h.description, frequency=h.frequency, created_at=h.created_at) for h in habits]

@app.get("/habits/{habit_id}", response_model=HabitRead)
def get_habit(habit_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit or habit.user_id != current_user.id:
            raise HTTPException(404, "Habit not found")
        return HabitRead(id=habit.id, title=habit.title, description=habit.description, frequency=habit.frequency, created_at=habit.created_at)

@app.patch("/habits/{habit_id}")
def update_habit(habit_id: int, habit_in: HabitCreate, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit or habit.user_id != current_user.id:
            raise HTTPException(404, "Habit not found")
        habit.title = habit_in.title
        habit.description = habit_in.description
        habit.frequency = habit_in.frequency
        session.add(habit)
        session.commit()
        session.refresh(habit)
        return {"status": "ok", "habit": {"id": habit.id, "title": habit.title}}

@app.delete("/habits/{habit_id}", status_code=204)
def delete_habit(habit_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit or habit.user_id != current_user.id:
            raise HTTPException(404, "Habit not found")
        session.delete(habit)
        session.commit()
        return

# ----- Habit completion endpoints -----
@app.post("/habits/{habit_id}/complete")
def complete_habit(habit_id: int, log_in: HabitLogCreate, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit or habit.user_id != current_user.id:
            raise HTTPException(404, "Habit not found")
        entry_date = log_in.date or date.today()
        # prevent duplicate for same day
        existing = session.exec(select(HabitLog).where(HabitLog.habit_id == habit_id, HabitLog.user_id == current_user.id, HabitLog.date == entry_date)).first()
        if existing:
            raise HTTPException(400, "Already logged for this date")
        log = HabitLog(habit_id=habit_id, user_id=current_user.id, date=entry_date, note=log_in.note)
        session.add(log)
        session.commit()
        session.refresh(log)
        return {"status": "ok", "date": str(log.date)}

@app.get("/habits/{habit_id}/log")
def habit_log(habit_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit_id, HabitLog.user_id == current_user.id).order_by(HabitLog.date.desc())).all()
        return [{"date": str(l.date), "note": l.note} for l in logs]

# ----- Basic stats -----
@app.get("/stats")
def stats(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        # total habits
        total = session.exec(select(Habit).where(Habit.user_id == current_user.id)).count()
        # recent 7-day completions
        seven_days_ago = date.today() - timedelta(days=6)
        rows = session.exec(select(HabitLog).where(HabitLog.user_id == current_user.id, HabitLog.date >= seven_days_ago)).all()
        # counts per day
        counts = {}
        for i in range(7):
            d = seven_days_ago + timedelta(days=i)
            counts[str(d)] = 0
        for r in rows:
            counts[str(r.date)] = counts.get(str(r.date), 0) + 1
        # simple streak calc: longest current daily streak across habits
        streaks = {}
        for habit in session.exec(select(Habit).where(Habit.user_id == current_user.id)).all():
            logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit.id, HabitLog.user_id == current_user.id).order_by(HabitLog.date.desc())).all()
            cur_streak = 0
            d = date.today()
            for log in logs:
                if log.date == d:
                    cur_streak += 1
                    d = d - timedelta(days=1)
                elif log.date < d:
                    break
            streaks[habit.id] = cur_streak
        return {"total_habits": total, "weekly_counts": counts, "streaks": streaks}

# ------------------------- end file -------------------------
