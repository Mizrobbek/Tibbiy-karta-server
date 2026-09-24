"""
Elektron Tibbiy Karta — REST API
Oilaviy poliklinika uchun. FastAPI + SQLite asosida.
Endi: foydalanuvchi kirishi (shifokor / bemor rollari) va
tashrifga "keyingi tashrif sanasi" (masalan, emlash rejasi) qo'shildi.
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, uuid, random, datetime, os, hashlib, secrets

DB_PATH = "tibbiy_karta.db"
app = FastAPI(title="Elektron Tibbiy Karta API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY, med_id TEXT UNIQUE, full_name TEXT NOT NULL,
            birth_date TEXT, gender TEXT, phone TEXT, address TEXT, family_doctor TEXT
        )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS visits (
            id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, date TEXT, doctor TEXT,
            complaint TEXT, diagnosis TEXT, prescription TEXT, next_visit_date TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL, full_name TEXT, patient_id TEXT
        )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT
        )""")
    # eski bazalarda "next_visit_date" ustuni bo'lmasligi mumkin — qo'shib qo'yamiz
    try:
        conn.execute("ALTER TABLE visits ADD COLUMN next_visit_date TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


init_db()


def gen_med_id() -> str:
    return f"UZ-MED-{random.randint(10**11, 10**12 - 1)}"


def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def current_user(authorization: Optional[str] = Header(None)):
    """'Authorization: Bearer <token>' headeridan foydalanuvchini topadi."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Kirish talab qilinadi")
    token = authorization.split(" ", 1)[1]
    conn = get_db()
    row = conn.execute(
        "SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token=?",
        (token,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Sessiya tugagan, qayta kiring")
    return dict(row)


def require_doctor(user=None):
    if user["role"] != "shifokor":
        raise HTTPException(403, "Faqat shifokorlar uchun")


# ---------- Sxema ----------

class RegisterIn(BaseModel):
    username: str
    password: str
    full_name: str
    role: str  # "shifokor" | "bemor"


class LoginIn(BaseModel):
    username: str
    password: str


class PatientIn(BaseModel):
    full_name: str
    birth_date: Optional[str] = None
    gender: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    family_doctor: Optional[str] = None


class VisitIn(BaseModel):
    date: str
    doctor: Optional[str] = None
    complaint: Optional[str] = None
    diagnosis: Optional[str] = None
    prescription: Optional[str] = None
    next_visit_date: Optional[str] = None


# ---------- Auth ----------

@app.post("/auth/register")
def register(r: RegisterIn, authorization: Optional[str] = Header(None)):
    if r.role not in ("shifokor", "bemor"):
        raise HTTPException(400, "role 'shifokor' yoki 'bemor' bo'lishi kerak")
    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (r.username,)).fetchone():
        conn.close()
        raise HTTPException(400, "Bu foydalanuvchi nomi band")
    uid = str(uuid.uuid4())
    patient_id = None
    if r.role == "bemor":
        # bemor ro'yxatdan o'tganda, unga o'z tibbiy kartasi avtomatik yaratiladi
        patient_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO patients (id, med_id, full_name) VALUES (?, ?, ?)",
            (patient_id, gen_med_id(), r.full_name)
        )
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, full_name, patient_id) VALUES (?, ?, ?, ?, ?, ?)",
        (uid, r.username, hash_pw(r.password), r.role, r.full_name, patient_id)
    )
    conn.commit()
    conn.close()
    return {"status": "ro'yxatdan o'tdi"}


@app.post("/auth/login")
def login(l: LoginIn):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (l.username, hash_pw(l.password))
    ).fetchone()
    if not user:
        conn.close()
        raise HTTPException(401, "Login yoki parol xato")
    token = secrets.token_hex(24)
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user["id"], datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return {"token": token, "role": user["role"], "full_name": user["full_name"], "patient_id": user["patient_id"]}


# ---------- Bemorlar (faqat shifokor uchun ro'yxat/qo'shish/o'chirish) ----------

@app.get("/patients")
def list_patients(q: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    if q:
        rows = conn.execute(
            "SELECT * FROM patients WHERE full_name LIKE ? OR med_id LIKE ?", (f"%{q}%", f"%{q}%")
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/patients")
def create_patient(p: PatientIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    pid = str(uuid.uuid4())
    med_id = gen_med_id()
    conn.execute(
        "INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (pid, med_id, p.full_name, p.birth_date, p.gender, p.phone, p.address, p.family_doctor)
    )
    conn.commit()
    conn.close()
    return {"id": pid, "med_id": med_id}


@app.get("/patients/{patient_id}")
def get_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "shifokor" and user["patient_id"] != patient_id:
        raise HTTPException(403, "Faqat o'z kartangizni ko'rishingiz mumkin")
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient:
        raise HTTPException(404, "Bemor topilmadi")
    visits = conn.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY date DESC", (patient_id,)).fetchall()
    conn.close()
    result = dict(patient)
    result["visits"] = [dict(v) for v in visits]
    return result


@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    conn.execute("DELETE FROM visits WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit()
    conn.close()
    return {"status": "o'chirildi"}


# ---------- Tashriflar (faqat shifokor yoza oladi) ----------

@app.post("/patients/{patient_id}/visits")
def add_visit(patient_id: str, v: VisitIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM patients WHERE id=?", (patient_id,)).fetchone():
        raise HTTPException(404, "Bemor topilmadi")
    vid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (vid, patient_id, v.date, v.doctor, v.complaint, v.diagnosis, v.prescription, v.next_visit_date)
    )
    conn.commit()
    conn.close()
    return {"id": vid}


# ---------- Eslatmalar: yaqinlashayotgan/o'tib ketgan keyingi tashriflar ----------

@app.get("/reminders")
def reminders(authorization: Optional[str] = Header(None)):
    """Shifokor uchun: rejalashtirilgan keyingi tashriflar (masalan, emlash) ro'yxati."""
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    rows = conn.execute("""
        SELECT visits.next_visit_date, visits.diagnosis, patients.id as patient_id,
               patients.full_name, patients.phone, patients.med_id
        FROM visits JOIN patients ON visits.patient_id = patients.id
        WHERE visits.next_visit_date IS NOT NULL AND visits.next_visit_date != ''
        ORDER BY visits.next_visit_date ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------- DMED bilan almashish ----------

@app.get("/dmed/export")
def dmed_export(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    result = {"system": "oilaviy-poliklinika-tibbiy-karta",
              "exportedAt": datetime.datetime.utcnow().isoformat(), "patients": []}
    for p in patients:
        visits = conn.execute("SELECT * FROM visits WHERE patient_id=?", (p["id"],)).fetchall()
        result["patients"].append({
            "medId": p["med_id"], "fullName": p["full_name"], "birthDate": p["birth_date"],
            "gender": p["gender"], "phone": p["phone"], "address": p["address"],
            "familyDoctor": p["family_doctor"],
            "encounters": [{
                "date": v["date"], "doctor": v["doctor"], "complaint": v["complaint"],
                "diagnosis": v["diagnosis"], "prescription": v["prescription"],
                "nextVisitDate": v["next_visit_date"]
            } for v in visits]
        })
    conn.close()
    return result


@app.post("/dmed/import")
def dmed_import(payload: dict, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    require_doctor(user)
    conn = get_db()
    added = 0
    for d in payload.get("patients", []):
        pid = str(uuid.uuid4())
        med_id = d.get("medId") or gen_med_id()
        conn.execute(
            "INSERT OR IGNORE INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (pid, med_id, d.get("fullName"), d.get("birthDate"), d.get("gender"),
             d.get("phone"), d.get("address"), d.get("familyDoctor"))
        )
        for e in d.get("encounters", []):
            conn.execute(
                "INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), pid, e.get("date"), e.get("doctor"), e.get("complaint"),
                 e.get("diagnosis"), e.get("prescription"), e.get("nextVisitDate"))
            )
        added += 1
    conn.commit()
    conn.close()
    return {"imported": added}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
