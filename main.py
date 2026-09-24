"""
Elektron Tibbiy Karta — REST API (v4)
Rollar: admin, shifokor, bemor.
Yangi: o'z login/parolini o'zgartirish, bemor-shifokor chat, shifokorga
reyting/sharh, admin va shifokor uchun statistika.
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, uuid, random, datetime, os, hashlib, secrets

DB_PATH = "tibbiy_karta.db"
app = FastAPI(title="Elektron Tibbiy Karta API", version="4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY, med_id TEXT UNIQUE, full_name TEXT NOT NULL,
            birth_date TEXT, gender TEXT, phone TEXT, address TEXT, family_doctor TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS visits (
            id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, date TEXT, doctor TEXT,
            complaint TEXT, diagnosis TEXT, prescription TEXT, next_visit_date TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            role TEXT NOT NULL, full_name TEXT, patient_id TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, sender_role TEXT, sender_name TEXT,
            body TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ratings (
            id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, patient_name TEXT, doctor_name TEXT,
            stars INTEGER, comment TEXT, created_at TEXT)""")
    try: conn.execute("ALTER TABLE visits ADD COLUMN next_visit_date TEXT")
    except sqlite3.OperationalError: pass
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        conn.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?,?,?,?,?)",
                      (str(uuid.uuid4()), "admin", hash_pw("admin123"), "admin", "Bosh administrator"))
    conn.commit()
    conn.close()


init_db()


def gen_med_id() -> str:
    return f"UZ-MED-{random.randint(10**11, 10**12 - 1)}"


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Kirish talab qilinadi")
    token = authorization.split(" ", 1)[1]
    conn = get_db()
    row = conn.execute(
        "SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token=?",
        (token,)).fetchone()
    conn.close()
    if not row: raise HTTPException(401, "Sessiya tugagan, qayta kiring")
    return dict(row)


def require_staff(user):
    if user["role"] not in ("shifokor", "admin"): raise HTTPException(403, "Bu amal faqat shifokor/admin uchun")


def require_admin(user):
    if user["role"] != "admin": raise HTTPException(403, "Bu amal faqat admin uchun")


def can_view_patient(user, patient_id):
    return user["role"] in ("shifokor", "admin") or user["patient_id"] == patient_id


def period_start(period: str) -> str:
    today = datetime.date.today()
    if period == "daily": start = today
    elif period == "weekly": start = today - datetime.timedelta(days=today.weekday())
    elif period == "monthly": start = today.replace(day=1)
    elif period == "yearly": start = today.replace(month=1, day=1)
    else: start = today - datetime.timedelta(days=3650)
    return start.isoformat()


# ---------- Sxema ----------
class LoginIn(BaseModel):
    username: str; password: str

class ChangeCredentialsIn(BaseModel):
    old_password: str
    new_username: Optional[str] = None
    new_password: Optional[str] = None

class UserCreateIn(BaseModel):
    username: str; password: str; full_name: str; role: str
    birth_date: Optional[str]=None; gender: Optional[str]=None; phone: Optional[str]=None
    address: Optional[str]=None; family_doctor: Optional[str]=None

class PatientIn(BaseModel):
    full_name: str; birth_date: Optional[str]=None; gender: Optional[str]=None
    phone: Optional[str]=None; address: Optional[str]=None; family_doctor: Optional[str]=None

class VisitIn(BaseModel):
    date: str; doctor: Optional[str]=None; complaint: Optional[str]=None
    diagnosis: Optional[str]=None; prescription: Optional[str]=None; next_visit_date: Optional[str]=None

class MessageIn(BaseModel):
    body: str

class RatingIn(BaseModel):
    doctor_name: str; stars: int; comment: Optional[str] = None


# ---------- Auth ----------
@app.post("/auth/login")
def login(l: LoginIn):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?",
                         (l.username, hash_pw(l.password))).fetchone()
    if not user:
        conn.close(); raise HTTPException(401, "Login yoki parol xato")
    token = secrets.token_hex(24)
    conn.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)",
                 (token, user["id"], datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"token": token, "role": user["role"], "full_name": user["full_name"], "patient_id": user["patient_id"]}


@app.post("/auth/change-credentials")
def change_credentials(body: ChangeCredentialsIn, authorization: Optional[str] = Header(None)):
    """Har bir foydalanuvchi (admin ham) faqat O'Z login/parolini shu orqali o'zgartiradi."""
    user = current_user(authorization)
    if user["password_hash"] != hash_pw(body.old_password):
        raise HTTPException(400, "Eski parol xato")
    conn = get_db()
    new_username = body.new_username.strip() if body.new_username else user["username"]
    if new_username != user["username"]:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (new_username,)).fetchone():
            conn.close(); raise HTTPException(400, "Bu foydalanuvchi nomi band")
    new_hash = hash_pw(body.new_password) if body.new_password else user["password_hash"]
    conn.execute("UPDATE users SET username=?, password_hash=? WHERE id=?", (new_username, new_hash, user["id"]))
    conn.commit(); conn.close()
    return {"status": "yangilandi", "username": new_username}


# ---------- Admin: foydalanuvchilar ----------
@app.get("/admin/users")
def list_users(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, full_name, patient_id FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/admin/users")
def create_user(u: UserCreateIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    if u.role not in ("admin", "shifokor", "bemor"): raise HTTPException(400, "role admin/shifokor/bemor bo'lishi kerak")
    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (u.username,)).fetchone():
        conn.close(); raise HTTPException(400, "Bu foydalanuvchi nomi band")
    uid = str(uuid.uuid4()); patient_id = None
    if u.role == "bemor":
        patient_id = str(uuid.uuid4())
        conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor) VALUES (?,?,?,?,?,?,?,?)",
                     (patient_id, gen_med_id(), u.full_name, u.birth_date, u.gender, u.phone, u.address, u.family_doctor))
    conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, patient_id) VALUES (?,?,?,?,?,?)",
                 (uid, u.username, hash_pw(u.password), u.role, u.full_name, patient_id))
    conn.commit(); conn.close()
    return {"id": uid, "patient_id": patient_id}


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target: raise HTTPException(404, "Topilmadi")
    if target["patient_id"]:
        conn.execute("DELETE FROM visits WHERE patient_id=?", (target["patient_id"],))
        conn.execute("DELETE FROM patients WHERE id=?", (target["patient_id"],))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    return {"status": "o'chirildi"}


# ---------- Bemorlar ----------
@app.get("/patients")
def list_patients(q: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    if q:
        rows = conn.execute("SELECT * FROM patients WHERE full_name LIKE ? OR med_id LIKE ?", (f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/patients")
def create_patient(p: PatientIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db(); pid = str(uuid.uuid4()); med_id = gen_med_id()
    conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor) VALUES (?,?,?,?,?,?,?,?)",
                 (pid, med_id, p.full_name, p.birth_date, p.gender, p.phone, p.address, p.family_doctor))
    conn.commit(); conn.close()
    return {"id": pid, "med_id": med_id}


@app.get("/patients/{patient_id}")
def get_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if not can_view_patient(user, patient_id): raise HTTPException(403, "Faqat o'z kartangizni ko'rishingiz mumkin")
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient: raise HTTPException(404, "Bemor topilmadi")
    visits = conn.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY date DESC", (patient_id,)).fetchall()
    conn.close()
    result = dict(patient); result["visits"] = [dict(v) for v in visits]
    return result


@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    conn.execute("DELETE FROM visits WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM messages WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM ratings WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit(); conn.close()
    return {"status": "o'chirildi"}


# ---------- Tashriflar ----------
@app.post("/patients/{patient_id}/visits")
def add_visit(patient_id: str, v: VisitIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM patients WHERE id=?", (patient_id,)).fetchone(): raise HTTPException(404, "Bemor topilmadi")
    vid = str(uuid.uuid4())
    conn.execute("INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date) VALUES (?,?,?,?,?,?,?,?)",
                 (vid, patient_id, v.date, v.doctor, v.complaint, v.diagnosis, v.prescription, v.next_visit_date))
    conn.commit(); conn.close()
    return {"id": vid}


# ---------- Eslatmalar ----------
@app.get("/reminders")
def reminders(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    rows = conn.execute("""SELECT visits.next_visit_date, visits.diagnosis, patients.id as patient_id,
        patients.full_name, patients.phone, patients.med_id FROM visits JOIN patients ON visits.patient_id = patients.id
        WHERE visits.next_visit_date IS NOT NULL AND visits.next_visit_date != '' ORDER BY visits.next_visit_date ASC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------- Chat (bemor <-> shifokor, bemor kartasi bo'yicha) ----------
@app.get("/patients/{patient_id}/messages")
def get_messages(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if not can_view_patient(user, patient_id): raise HTTPException(403, "Ruxsat yo'q")
    conn = get_db()
    rows = conn.execute("SELECT * FROM messages WHERE patient_id=? ORDER BY created_at ASC", (patient_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/patients/{patient_id}/messages")
def send_message(patient_id: str, m: MessageIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if not can_view_patient(user, patient_id): raise HTTPException(403, "Ruxsat yo'q")
    conn = get_db()
    mid = str(uuid.uuid4())
    conn.execute("INSERT INTO messages (id, patient_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, patient_id, user["role"], user["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}


# ---------- Shifokorga reyting/sharh (faqat bemor, o'zining kartasi bo'yicha) ----------
@app.get("/patients/{patient_id}/ratings")
def get_ratings(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if not can_view_patient(user, patient_id): raise HTTPException(403, "Ruxsat yo'q")
    conn = get_db()
    rows = conn.execute("SELECT * FROM ratings WHERE patient_id=? ORDER BY created_at DESC", (patient_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/patients/{patient_id}/ratings")
def add_rating(patient_id: str, r: RatingIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "bemor" or user["patient_id"] != patient_id:
        raise HTTPException(403, "Faqat o'zingiz uchun, bemor sifatida baholay olasiz")
    if not (1 <= r.stars <= 5): raise HTTPException(400, "Baho 1 dan 5 gacha bo'lishi kerak")
    conn = get_db()
    patient = conn.execute("SELECT full_name FROM patients WHERE id=?", (patient_id,)).fetchone()
    rid = str(uuid.uuid4())
    conn.execute("INSERT INTO ratings (id, patient_id, patient_name, doctor_name, stars, comment, created_at) VALUES (?,?,?,?,?,?,?)",
                 (rid, patient_id, patient["full_name"] if patient else "", r.doctor_name, r.stars, r.comment,
                  datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": rid}


@app.get("/doctors/summary")
def doctors_summary(authorization: Optional[str] = Header(None)):
    """Har bir shifokor uchun: umumiy tashrif soni va o'rtacha reyting (staff uchun)."""
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    visit_counts = conn.execute("""SELECT doctor, COUNT(*) as cnt FROM visits
        WHERE doctor IS NOT NULL AND doctor != '' GROUP BY doctor""").fetchall()
    rating_rows = conn.execute("""SELECT doctor_name, AVG(stars) as avg_stars, COUNT(*) as rcount
        FROM ratings GROUP BY doctor_name""").fetchall()
    conn.close()
    ratings_map = {r["doctor_name"]: {"avg_stars": round(r["avg_stars"], 1), "count": r["rcount"]} for r in rating_rows}
    result = []
    for v in visit_counts:
        rt = ratings_map.get(v["doctor"], {"avg_stars": None, "count": 0})
        result.append({"doctor": v["doctor"], "visits": v["cnt"], "avg_stars": rt["avg_stars"], "rating_count": rt["count"]})
    result.sort(key=lambda x: x["visits"], reverse=True)
    return result


# ---------- Statistika ----------
@app.get("/admin/stats")
def admin_stats(period: str = "daily", authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    start = period_start(period)
    conn = get_db()
    visits = conn.execute("""SELECT visits.*, patients.full_name as patient_name FROM visits
        JOIN patients ON visits.patient_id = patients.id WHERE visits.date >= ? ORDER BY visits.date DESC""", (start,)).fetchall()
    top_doctors = conn.execute("""SELECT doctor, COUNT(*) as cnt FROM visits
        WHERE date >= ? AND doctor IS NOT NULL AND doctor != '' GROUP BY doctor ORDER BY cnt DESC LIMIT 10""", (start,)).fetchall()
    total_patients = conn.execute("SELECT COUNT(*) as c FROM patients").fetchone()["c"]
    conn.close()
    return {
        "period": period, "since": start,
        "visit_count": len(visits),
        "patients_seen": [{"patient_name": v["patient_name"], "date": v["date"], "doctor": v["doctor"]} for v in visits],
        "top_doctors": [{"doctor": d["doctor"], "visits": d["cnt"]} for d in top_doctors],
        "total_patients_in_system": total_patients
    }


@app.get("/doctor/stats")
def doctor_stats(period: str = "daily", authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "shifokor": raise HTTPException(403, "Faqat shifokor uchun")
    start = period_start(period)
    conn = get_db()
    my_visits = conn.execute("""SELECT visits.*, patients.full_name as patient_name FROM visits
        JOIN patients ON visits.patient_id = patients.id WHERE visits.date >= ? AND visits.doctor = ?
        ORDER BY visits.date DESC""", (start, user["full_name"])).fetchall()
    rating = conn.execute("SELECT AVG(stars) as avg_stars, COUNT(*) as cnt FROM ratings WHERE doctor_name=?",
                           (user["full_name"],)).fetchone()
    conn.close()
    return {
        "period": period, "visit_count": len(my_visits),
        "visits": [{"patient_name": v["patient_name"], "date": v["date"], "diagnosis": v["diagnosis"]} for v in my_visits],
        "avg_stars": round(rating["avg_stars"], 1) if rating["avg_stars"] else None,
        "rating_count": rating["cnt"]
    }


# ---------- DMED ----------
@app.get("/dmed/export")
def dmed_export(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    result = {"system": "oilaviy-poliklinika-tibbiy-karta", "exportedAt": datetime.datetime.utcnow().isoformat(), "patients": []}
    for p in patients:
        visits = conn.execute("SELECT * FROM visits WHERE patient_id=?", (p["id"],)).fetchall()
        result["patients"].append({
            "medId": p["med_id"], "fullName": p["full_name"], "birthDate": p["birth_date"], "gender": p["gender"],
            "phone": p["phone"], "address": p["address"], "familyDoctor": p["family_doctor"],
            "encounters": [{"date": v["date"], "doctor": v["doctor"], "complaint": v["complaint"],
                             "diagnosis": v["diagnosis"], "prescription": v["prescription"],
                             "nextVisitDate": v["next_visit_date"]} for v in visits]})
    conn.close()
    return result


@app.post("/dmed/import")
def dmed_import(payload: dict, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db(); added = 0
    for d in payload.get("patients", []):
        pid = str(uuid.uuid4()); med_id = d.get("medId") or gen_med_id()
        conn.execute("INSERT OR IGNORE INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor) VALUES (?,?,?,?,?,?,?,?)",
                     (pid, med_id, d.get("fullName"), d.get("birthDate"), d.get("gender"), d.get("phone"), d.get("address"), d.get("familyDoctor")))
        for e in d.get("encounters", []):
            conn.execute("INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date) VALUES (?,?,?,?,?,?,?,?)",
                         (str(uuid.uuid4()), pid, e.get("date"), e.get("doctor"), e.get("complaint"), e.get("diagnosis"),
                          e.get("prescription"), e.get("nextVisitDate")))
        added += 1
    conn.commit(); conn.close()
    return {"imported": added}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
