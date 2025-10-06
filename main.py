# main.py
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, date
import sqlite3
from typing import List
from contextlib import asynccontextmanager
import math

# --- CONFIG ---
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- DATABASE ---
DATABASE_URL = "voicenotes.db"

def get_db():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    with get_db() as conn:
        # User Table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        # Notes Table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            creation_date TEXT NOT NULL,
            language TEXT NOT NULL,
            transcription_time_minutes INTEGER NOT NULL,
            storage_size_mb REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """)
        conn.commit()

def add_mock_data():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", ("user@example.com",))
        user_exists = cursor.fetchone()

        if not user_exists:
            print("✅ Adding mock data...")
            hashed_password = hash_password("password123")
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", ("Sagar Sharma", "user@example.com", hashed_password))
            user_id = cursor.lastrowid
            mock_notes = [
                (user_id, "Meeting with Marketing Team", "Discussed Q2 strategy...", (date.today() - timedelta(days=2)).isoformat(), "English", 25, 12.5),
                (user_id, "Lecture - Quantum Physics", "Spin particle theory...", (date.today() - timedelta(days=3)).isoformat(), "English", 60, 30.0),
                (user_id, "Personal Diary Entry", "A personal reflection...", (date.today() - timedelta(days=1)).isoformat(), "Hindi", 10, 5.0),
            ]
            cursor.executemany("INSERT INTO notes (user_id, title, description, creation_date, language, transcription_time_minutes, storage_size_mb) VALUES (?, ?, ?, ?, ?, ?, ?)", mock_notes)
            conn.commit()
            print("✔️ Mock data added successfully.")
            print("\n--- DEMO USER ---\nEmail: user@example.com\nPassword: password123\n-------------------\n")
        else:
            print("ℹ️ Mock user already exists. Skipping data insertion.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("--- Application starting up ---")
    setup_database()
    add_mock_data()
    print("--- Startup complete ---")
    yield
    # Code to run on shutdown
    print("--- Application shutting down ---")

# --- APP SETUP ---
app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODELS ---
class UserCreate(BaseModel): name: str; email: str; password: str
class Token(BaseModel): access_token: str; token_type: str
class User(BaseModel): id: int; name: str; email: str
class ActivityStats(BaseModel): notes_this_week: int; total_transcription_time: int; languages: List[str]
class StorageStats(BaseModel): used_gb: float; total_gb: float
class RecentNote(BaseModel): title: str; meta: str; desc: str
class DashboardData(BaseModel): user: User; activity: ActivityStats; storage: StorageStats; recent_notes: List[RecentNote]
# ▼▼▼ NEW RESPONSE MODEL ▼▼▼
class TranscriptionResponse(BaseModel): msg: str; note_id: int
# ▲▲▲ END NEW MODEL ▲▲▲


# --- UTILS ---
def hash_password(password: str): return pwd_context.hash(password)
def verify_password(plain_password: str, hashed_password: str): return pwd_context.verify(plain_password, hashed_password)
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
def get_current_user(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    if user is None: raise credentials_exception
    return User(id=user["id"], name=user["name"], email=user["email"])

# --- ROUTES ---
@app.post("/register")
def register(user: UserCreate, db: sqlite3.Connection = Depends(get_db)):
    try:
        db.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (user.name, user.email, hash_password(user.password)))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"msg": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (form_data.username,))
    db_user = cursor.fetchone()
    if not db_user or not verify_password(form_data.password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": db_user["email"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# ▼▼▼ NEW TRANSCRIPTION ENDPOINT ▼▼▼
@app.post("/transcribe", response_model=TranscriptionResponse)
async def transcribe_audio(
    current_user: User = Depends(get_current_user),
    file: UploadFile = File(...),
    db: sqlite3.Connection = Depends(get_db)
):
    try:
        # Simulate processing
        contents = await file.read()
        storage_mb = len(contents) / (1024 * 1024)
        
        # Simulate transcription time (e.g., 1 minute per 0.2 MB of audio)
        duration_minutes = math.ceil(storage_mb / 0.2)
        
        # Create a dummy title and description
        title = f"Transcription - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        description = f"This is an AI-generated summary for the file '{file.filename}'. The content has been processed and is ready for review."

        # Insert into database
        cursor = db.cursor()
        cursor.execute(
            """INSERT INTO notes (user_id, title, description, creation_date, language, transcription_time_minutes, storage_size_mb)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                current_user.id,
                title,
                description,
                date.today().isoformat(),
                "English", # Default language
                duration_minutes,
                round(storage_mb, 2)
            )
        )
        note_id = cursor.lastrowid
        db.commit()
        
        return {"msg": "File transcribed successfully", "note_id": note_id}

    except Exception as e:
        print(f"Error during transcription: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during transcription.")
# ▲▲▲ END NEW ENDPOINT ▲▲▲


@app.get("/dashboard-data", response_model=DashboardData)
def get_dashboard_data(current_user: User = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    user_id = current_user.id
    cursor = db.cursor()
    one_week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    cursor.execute("SELECT COUNT(*) FROM notes WHERE user_id = ? AND creation_date >= ?", (user_id, one_week_ago))
    notes_this_week = cursor.fetchone()[0]
    cursor.execute("SELECT SUM(transcription_time_minutes) FROM notes WHERE user_id = ?", (user_id,))
    total_time = cursor.fetchone()[0] or 0
    cursor.execute("SELECT DISTINCT language FROM notes WHERE user_id = ?", (user_id,))
    languages = [row[0] for row in cursor.fetchall()]
    activity = ActivityStats(notes_this_week=notes_this_week, total_transcription_time=total_time, languages=languages)
    cursor.execute("SELECT SUM(storage_size_mb) FROM notes WHERE user_id = ?", (user_id,))
    total_mb = cursor.fetchone()[0] or 0
    used_gb = round(total_mb / 1024, 2)
    storage = StorageStats(used_gb=used_gb, total_gb=100.0)
    
    # ▼▼▼ MODIFIED QUERY TO INCLUDE DURATION ▼▼▼
    cursor.execute(
        "SELECT title, description, creation_date, language, transcription_time_minutes FROM notes WHERE user_id = ? ORDER BY creation_date DESC LIMIT 3", 
        (user_id,)
    )
    # ▲▲▲ END MODIFICATION ▲▲▲
    
    notes_from_db = cursor.fetchall()
    recent_notes = []
    for note in notes_from_db:
        dt_obj = datetime.fromisoformat(note["creation_date"])
        formatted_date = dt_obj.strftime("%b %d, %Y")
        
        # ▼▼▼ MODIFIED META STRING TO INCLUDE DURATION ▼▼▼
        meta_string = f"{formatted_date} • {note['language']} • {note['transcription_time_minutes']} mins"
        recent_notes.append(RecentNote(title=note["title"], desc=note["description"], meta=meta_string))
        # ▲▲▲ END MODIFICATION ▲▲▲

    return DashboardData(user=current_user, activity=activity, storage=storage, recent_notes=recent_notes)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)