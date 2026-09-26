"""
Elektron Tibbiy Karta — REST API (v5)
Profil (rasm/email/telefon), admin tomonidan tahrirlash, telefon orqali
parol tiklash, admin<->shifokor/bemor "support" chat qo'shildi.
"""
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, uuid, random, datetime, os, hashlib, secrets

DB_PATH = "tibbiy_karta.db"
app = FastAPI(title="Elektron Tibbiy Karta API", version="5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS patients (id TEXT PRIMARY KEY, med_id TEXT UNIQUE,
        full_name TEXT NOT NULL, birth_date TEXT, gender TEXT, phone TEXT, address TEXT, family_doctor TEXT,
        region TEXT, district TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS visits (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        date TEXT, doctor TEXT, complaint TEXT, diagnosis TEXT, prescription TEXT, next_visit_date TEXT, inn_name TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL, full_name TEXT, patient_id TEXT,
        email TEXT, phone TEXT, avatar TEXT, region TEXT, district TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        sender_role TEXT, sender_name TEXT, body TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ratings (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        patient_name TEXT, doctor_name TEXT, stars INTEGER, comment TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS support_messages (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        sender_role TEXT, sender_name TEXT, body TEXT, created_at TEXT)""")
    for stmt in ["ALTER TABLE visits ADD COLUMN next_visit_date TEXT",
                 "ALTER TABLE visits ADD COLUMN inn_name TEXT",
                 "ALTER TABLE users ADD COLUMN email TEXT", "ALTER TABLE users ADD COLUMN phone TEXT",
                 "ALTER TABLE users ADD COLUMN avatar TEXT", "ALTER TABLE users ADD COLUMN region TEXT",
                 "ALTER TABLE users ADD COLUMN district TEXT", "ALTER TABLE patients ADD COLUMN region TEXT",
                 "ALTER TABLE patients ADD COLUMN district TEXT"]:
        try: conn.execute(stmt)
        except sqlite3.OperationalError: pass
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        conn.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?,?,?,?,?)",
                      (str(uuid.uuid4()), "admin", hash_pw("admin123"), "admin", "Bosh administrator"))
    conn.commit(); conn.close()

init_db()

def gen_med_id(): return f"UZ-MED-{random.randint(10**11, 10**12 - 1)}"

def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "Kirish talab qilinadi")
    token = authorization.split(" ", 1)[1]
    conn = get_db()
    row = conn.execute("SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token=?", (token,)).fetchone()
    conn.close()
    if not row: raise HTTPException(401, "Sessiya tugagan, qayta kiring")
    return dict(row)

def require_staff(u):
    if u["role"] not in ("shifokor","admin"): raise HTTPException(403, "Faqat shifokor/admin uchun")
def require_admin(u):
    if u["role"] != "admin": raise HTTPException(403, "Faqat admin uchun")
def can_view_patient(u, pid): return u["role"] in ("shifokor","admin") or u["patient_id"] == pid

def period_start(period):
    today = datetime.date.today()
    if period=="daily": start = today
    elif period=="weekly": start = today - datetime.timedelta(days=today.weekday())
    elif period=="monthly": start = today.replace(day=1)
    elif period=="yearly": start = today.replace(month=1, day=1)
    else: start = today - datetime.timedelta(days=3650)
    return start.isoformat()

class LoginIn(BaseModel): username: str; password: str
class ChangeCredentialsIn(BaseModel):
    old_password: str; new_username: Optional[str]=None; new_password: Optional[str]=None
class ProfileUpdateIn(BaseModel):
    full_name: Optional[str]=None; email: Optional[str]=None; phone: Optional[str]=None; avatar: Optional[str]=None
class ResetPasswordIn(BaseModel): username: str; phone: str; new_password: str
class UserCreateIn(BaseModel):
    username: str; password: str; full_name: str; role: str
    birth_date: Optional[str]=None; gender: Optional[str]=None; phone: Optional[str]=None
    address: Optional[str]=None; family_doctor: Optional[str]=None; email: Optional[str]=None
    region: Optional[str]=None; district: Optional[str]=None
class UserEditIn(BaseModel):
    full_name: Optional[str]=None; email: Optional[str]=None; phone: Optional[str]=None
    birth_date: Optional[str]=None; gender: Optional[str]=None; address: Optional[str]=None; family_doctor: Optional[str]=None
    region: Optional[str]=None; district: Optional[str]=None
class PatientIn(BaseModel):
    full_name: str; birth_date: Optional[str]=None; gender: Optional[str]=None
    phone: Optional[str]=None; address: Optional[str]=None; family_doctor: Optional[str]=None
    region: Optional[str]=None; district: Optional[str]=None
class VisitIn(BaseModel):
    date: str; doctor: Optional[str]=None; complaint: Optional[str]=None
    diagnosis: Optional[str]=None; prescription: Optional[str]=None; next_visit_date: Optional[str]=None
    inn_name: Optional[str]=None
class MessageIn(BaseModel): body: str
class RatingIn(BaseModel): doctor_name: str; stars: int; comment: Optional[str]=None

# ---------- Auth ----------
@app.post("/auth/login")
def login(l: LoginIn):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (l.username, hash_pw(l.password))).fetchone()
    if not user: conn.close(); raise HTTPException(401, "Login yoki parol xato")
    token = secrets.token_hex(24)
    conn.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)", (token, user["id"], datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"token": token, "role": user["role"], "full_name": user["full_name"], "patient_id": user["patient_id"],
            "username": user["username"], "email": user["email"], "phone": user["phone"], "avatar": user["avatar"]}

@app.post("/auth/change-credentials")
def change_credentials(body: ChangeCredentialsIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["password_hash"] != hash_pw(body.old_password): raise HTTPException(400, "Eski parol xato")
    conn = get_db()
    new_username = body.new_username.strip() if body.new_username else user["username"]
    if new_username != user["username"] and conn.execute("SELECT 1 FROM users WHERE username=?", (new_username,)).fetchone():
        conn.close(); raise HTTPException(400, "Bu foydalanuvchi nomi band")
    new_hash = hash_pw(body.new_password) if body.new_password else user["password_hash"]
    conn.execute("UPDATE users SET username=?, password_hash=? WHERE id=?", (new_username, new_hash, user["id"]))
    conn.commit(); conn.close()
    return {"status":"yangilandi", "username": new_username}

@app.post("/auth/reset-password")
def reset_password(body: ResetPasswordIn):
    """Login/parolni telefon raqami orqali tiklash (profilda oldindan telefon kiritilgan bo'lishi shart)."""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND phone=?", (body.username, body.phone)).fetchone()
    if not user: conn.close(); raise HTTPException(404, "Login yoki telefon raqam mos kelmadi")
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_pw(body.new_password), user["id"]))
    conn.commit(); conn.close()
    return {"status":"parol tiklandi"}

@app.put("/profile")
def update_profile(body: ProfileUpdateIn, authorization: Optional[str] = Header(None)):
    """Har kim faqat O'Z profilini (ism, email, telefon, rasm) tahrirlaydi."""
    user = current_user(authorization)
    conn = get_db()
    fields = {"full_name": body.full_name, "email": body.email, "phone": body.phone, "avatar": body.avatar}
    for k, v in fields.items():
        if v is not None: conn.execute(f"UPDATE users SET {k}=? WHERE id=?", (v, user["id"]))
    if body.full_name and user["patient_id"]:
        conn.execute("UPDATE patients SET full_name=? WHERE id=?", (body.full_name, user["patient_id"]))
    conn.commit(); conn.close()
    return {"status":"yangilandi"}

# ---------- Admin: foydalanuvchilar ----------
@app.get("/admin/users")
def list_users(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, full_name, patient_id, email, phone, avatar, region, district FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/admin/users")
def create_user(u: UserCreateIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    if u.role not in ("admin","shifokor","bemor"): raise HTTPException(400, "role admin/shifokor/bemor bo'lishi kerak")
    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (u.username,)).fetchone():
        conn.close(); raise HTTPException(400, "Bu foydalanuvchi nomi band")
    uid = str(uuid.uuid4()); patient_id = None
    if u.role == "bemor":
        patient_id = str(uuid.uuid4())
        conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor, region, district) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (patient_id, gen_med_id(), u.full_name, u.birth_date, u.gender, u.phone, u.address, u.family_doctor, u.region, u.district))
    conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, patient_id, email, phone, region, district) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (uid, u.username, hash_pw(u.password), u.role, u.full_name, patient_id, u.email, u.phone, u.region, u.district))
    conn.commit(); conn.close()
    return {"id": uid, "patient_id": patient_id}

@app.put("/admin/users/{user_id}")
def edit_user(user_id: str, u: UserEditIn, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target: conn.close(); raise HTTPException(404, "Topilmadi")
    if u.full_name is not None: conn.execute("UPDATE users SET full_name=? WHERE id=?", (u.full_name, user_id))
    if u.email is not None: conn.execute("UPDATE users SET email=? WHERE id=?", (u.email, user_id))
    if u.phone is not None: conn.execute("UPDATE users SET phone=? WHERE id=?", (u.phone, user_id))
    if u.region is not None: conn.execute("UPDATE users SET region=? WHERE id=?", (u.region, user_id))
    if u.district is not None: conn.execute("UPDATE users SET district=? WHERE id=?", (u.district, user_id))
    if target["patient_id"]:
        for field, val in [("full_name",u.full_name),("birth_date",u.birth_date),("gender",u.gender),
                            ("address",u.address),("family_doctor",u.family_doctor),("region",u.region),("district",u.district)]:
            if val is not None: conn.execute(f"UPDATE patients SET {field}=? WHERE id=?", (val, target["patient_id"]))
        if u.phone is not None: conn.execute("UPDATE patients SET phone=? WHERE id=?", (u.phone, target["patient_id"]))
    conn.commit(); conn.close()
    return {"status":"yangilandi"}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not target: raise HTTPException(404, "Topilmadi")
    if target["patient_id"]:
        conn.execute("DELETE FROM visits WHERE patient_id=?", (target["patient_id"],))
        conn.execute("DELETE FROM messages WHERE patient_id=?", (target["patient_id"],))
        conn.execute("DELETE FROM ratings WHERE patient_id=?", (target["patient_id"],))
        conn.execute("DELETE FROM patients WHERE id=?", (target["patient_id"],))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM support_messages WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    return {"status":"o'chirildi"}

@app.get("/doctors/list")
def doctors_list(authorization: Optional[str] = Header(None)):
    """Bemor uchun: shifokorlar ro'yxati (qidirish uchun)."""
    current_user(authorization)
    conn = get_db()
    rows = conn.execute("SELECT full_name, phone, email FROM users WHERE role='shifokor'").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------- Bemorlar ----------
@app.get("/patients")
def list_patients(q: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    rows = conn.execute("SELECT * FROM patients WHERE full_name LIKE ? OR med_id LIKE ?", (f"%{q}%", f"%{q}%")).fetchall() if q else conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/patients")
def create_patient(p: PatientIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db(); pid = str(uuid.uuid4()); med_id = gen_med_id()
    conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor, region, district) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (pid, med_id, p.full_name, p.birth_date, p.gender, p.phone, p.address, p.family_doctor, p.region, p.district))
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
    for t in ["visits","messages","ratings"]: conn.execute(f"DELETE FROM {t} WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit(); conn.close()
    return {"status":"o'chirildi"}

@app.post("/patients/{patient_id}/visits")
def add_visit(patient_id: str, v: VisitIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM patients WHERE id=?", (patient_id,)).fetchone(): raise HTTPException(404, "Bemor topilmadi")
    vid = str(uuid.uuid4())
    conn.execute("INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date, inn_name) VALUES (?,?,?,?,?,?,?,?,?)",
                 (vid, patient_id, v.date, v.doctor, v.complaint, v.diagnosis, v.prescription, v.next_visit_date, v.inn_name))
    conn.commit(); conn.close()
    return {"id": vid}

@app.get("/reminders")
def reminders(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    rows = conn.execute("""SELECT visits.next_visit_date, visits.diagnosis, patients.id as patient_id,
        patients.full_name, patients.phone, patients.med_id FROM visits JOIN patients ON visits.patient_id = patients.id
        WHERE visits.next_visit_date IS NOT NULL AND visits.next_visit_date != '' ORDER BY visits.next_visit_date ASC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/messages/inbox")
def messages_inbox(authorization: Optional[str] = Header(None)):
    """Shifokor/admin uchun: kim yozgan bemorlar ro'yxati, so'nggi xabar bilan."""
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    rows = conn.execute("""SELECT patients.id as patient_id, patients.full_name,
        MAX(messages.created_at) as last_at,
        (SELECT body FROM messages m2 WHERE m2.patient_id = patients.id ORDER BY m2.created_at DESC LIMIT 1) as last_body
        FROM messages JOIN patients ON messages.patient_id = patients.id
        GROUP BY patients.id ORDER BY last_at DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------- Bemor<->shifokor chat (bemor kartasi bo'yicha) ----------
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
    conn = get_db(); mid = str(uuid.uuid4())
    conn.execute("INSERT INTO messages (id, patient_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, patient_id, user["role"], user["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}

# ---------- Admin bilan aloqa (support chat) ----------
@app.get("/support/messages/me")
def my_support_messages(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    rows = conn.execute("SELECT * FROM support_messages WHERE user_id=? ORDER BY created_at ASC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/support/messages/me")
def send_my_support_message(m: MessageIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db(); mid = str(uuid.uuid4())
    conn.execute("INSERT INTO support_messages (id, user_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, user["id"], user["role"], user["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}

@app.get("/support/threads")
def support_threads(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    rows = conn.execute("""SELECT users.id as user_id, users.full_name, users.role,
        MAX(support_messages.created_at) as last_at FROM support_messages
        JOIN users ON users.id = support_messages.user_id GROUP BY users.id ORDER BY last_at DESC""").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/support/messages/{user_id}")
def support_messages_for_user(user_id: str, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db()
    rows = conn.execute("SELECT * FROM support_messages WHERE user_id=? ORDER BY created_at ASC", (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/support/messages/{user_id}")
def admin_reply_support(user_id: str, m: MessageIn, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db(); mid = str(uuid.uuid4())
    conn.execute("INSERT INTO support_messages (id, user_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, user_id, "admin", admin["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}

# ---------- Reyting ----------
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
    if user["role"] != "bemor" or user["patient_id"] != patient_id: raise HTTPException(403, "Faqat o'zingiz uchun")
    if not (1 <= r.stars <= 5): raise HTTPException(400, "Baho 1 dan 5 gacha")
    conn = get_db()
    patient = conn.execute("SELECT full_name FROM patients WHERE id=?", (patient_id,)).fetchone()
    rid = str(uuid.uuid4())
    conn.execute("INSERT INTO ratings (id, patient_id, patient_name, doctor_name, stars, comment, created_at) VALUES (?,?,?,?,?,?,?)",
                 (rid, patient_id, patient["full_name"] if patient else "", r.doctor_name, r.stars, r.comment, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": rid}

@app.get("/doctors/summary")
def doctors_summary(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    vc = conn.execute("SELECT doctor, COUNT(*) as cnt FROM visits WHERE doctor IS NOT NULL AND doctor != '' GROUP BY doctor").fetchall()
    rr = conn.execute("SELECT doctor_name, AVG(stars) as avg_stars, COUNT(*) as rcount FROM ratings GROUP BY doctor_name").fetchall()
    conn.close()
    rmap = {r["doctor_name"]: {"avg_stars": round(r["avg_stars"],1), "count": r["rcount"]} for r in rr}
    out = [{"doctor": v["doctor"], "visits": v["cnt"], **rmap.get(v["doctor"], {"avg_stars": None, "count": 0})} for v in vc]
    out.sort(key=lambda x: x["visits"], reverse=True)
    return out

# ---------- Statistika ----------
@app.get("/admin/stats")
def admin_stats(period: str = "daily", authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    start = period_start(period)
    conn = get_db()
    visits = conn.execute("""SELECT visits.*, patients.full_name as patient_name FROM visits
        JOIN patients ON visits.patient_id = patients.id WHERE visits.date >= ? ORDER BY visits.date DESC""", (start,)).fetchall()
    top_doctors = conn.execute("""SELECT doctor, COUNT(*) as cnt FROM visits WHERE date >= ? AND doctor IS NOT NULL AND doctor != ''
        GROUP BY doctor ORDER BY cnt DESC LIMIT 10""", (start,)).fetchall()
    total_patients = conn.execute("SELECT COUNT(*) as c FROM patients").fetchone()["c"]
    total_doctors = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='shifokor'").fetchone()["c"]
    conn.close()
    return {"period": period, "visit_count": len(visits),
            "patients_seen": [{"patient_name": v["patient_name"], "date": v["date"], "doctor": v["doctor"]} for v in visits],
            "top_doctors": [{"doctor": d["doctor"], "visits": d["cnt"]} for d in top_doctors],
            "total_patients_in_system": total_patients, "total_doctors": total_doctors}

@app.get("/doctor/stats")
def doctor_stats(period: str = "daily", authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "shifokor": raise HTTPException(403, "Faqat shifokor uchun")
    start = period_start(period)
    conn = get_db()
    my_visits = conn.execute("""SELECT visits.*, patients.full_name as patient_name FROM visits
        JOIN patients ON visits.patient_id = patients.id WHERE visits.date >= ? AND visits.doctor = ? ORDER BY visits.date DESC""",
        (start, user["full_name"])).fetchall()
    rating = conn.execute("SELECT AVG(stars) as avg_stars, COUNT(*) as cnt FROM ratings WHERE doctor_name=?", (user["full_name"],)).fetchone()
    conn.close()
    return {"period": period, "visit_count": len(my_visits),
            "visits": [{"patient_name": v["patient_name"], "date": v["date"], "diagnosis": v["diagnosis"]} for v in my_visits],
            "avg_stars": round(rating["avg_stars"],1) if rating["avg_stars"] else None, "rating_count": rating["cnt"]}

# ---------- DMED ----------
@app.get("/dmed/export")
def dmed_export(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients").fetchall()
    result = {"system":"oilaviy-poliklinika-tibbiy-karta", "exportedAt": datetime.datetime.utcnow().isoformat(), "patients": []}
    for p in patients:
        visits = conn.execute("SELECT * FROM visits WHERE patient_id=?", (p["id"],)).fetchall()
        result["patients"].append({"medId": p["med_id"], "fullName": p["full_name"], "birthDate": p["birth_date"],
            "gender": p["gender"], "phone": p["phone"], "address": p["address"], "familyDoctor": p["family_doctor"],
            "encounters": [{"date": v["date"], "doctor": v["doctor"], "complaint": v["complaint"], "diagnosis": v["diagnosis"],
                            "prescription": v["prescription"], "nextVisitDate": v["next_visit_date"], "innName": v["inn_name"]} for v in visits]})
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
                         (str(uuid.uuid4()), pid, e.get("date"), e.get("doctor"), e.get("complaint"), e.get("diagnosis"), e.get("prescription"), e.get("nextVisitDate")))
        added += 1
    conn.commit(); conn.close()
    return {"imported": added}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
