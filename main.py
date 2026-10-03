"""
Elektron Tibbiy Karta — REST API (v6, koʻp-klinikali / multi-tenant)
Rollar: super_admin (klinikalarni yaratadi), admin (oʻz klinikasini boshqaradi),
shifokor, bemor. Har bir klinika maʼlumotlari butunlay ajratilgan.
"""
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, uuid, random, datetime, os, hashlib, secrets, re

DB_PATH = "tibbiy_karta.db"
app = FastAPI(title="Elektron Tibbiy Karta API", version="6.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def normalize_phone(s):
    """Telefonni '998901234567' ko'rinishiga keltiradi; noto'g'ri bo'lsa '' qaytaradi."""
    digits = re.sub(r"\D", "", s or "")
    if len(digits) == 9: digits = "+998" + digits
    return digits if (len(digits) == 12 and digits.startswith("+998")) else ""

def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    conn.create_function("norm_phone", 1, lambda v: normalize_phone(v) or None)
    return conn

ALLOW_SELF_REGISTRATION = os.environ.get("ALLOW_SELF_REGISTRATION", "1") == "1"
ROLE_GROUPS = {"bemor": ("bemor",), "shifokor": ("shifokor",), "admin": ("admin", "super_admin")}

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
def gen_med_id(): return f"UZ-MED-{random.randint(10**11, 10**12 - 1)}"

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS clinics (id TEXT PRIMARY KEY, name TEXT NOT NULL,
        region TEXT, district TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS patients (id TEXT PRIMARY KEY, med_id TEXT UNIQUE,
        full_name TEXT NOT NULL, birth_date TEXT, gender TEXT, phone TEXT, address TEXT, family_doctor TEXT,
        region TEXT, district TEXT, clinic_id TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS visits (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        date TEXT, doctor TEXT, complaint TEXT, diagnosis TEXT, prescription TEXT, next_visit_date TEXT, inn_name TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL, full_name TEXT, patient_id TEXT,
        email TEXT, phone TEXT, avatar TEXT, region TEXT, district TEXT, clinic_id TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        sender_role TEXT, sender_name TEXT, body TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ratings (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL,
        patient_name TEXT, doctor_name TEXT, stars INTEGER, comment TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS support_messages (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
        sender_role TEXT, sender_name TEXT, body TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS appointments (id TEXT PRIMARY KEY, clinic_id TEXT NOT NULL,
        patient_id TEXT NOT NULL, patient_name TEXT, doctor_name TEXT, date TEXT, queue_number INTEGER,
        status TEXT DEFAULT 'kutilmoqda', created_at TEXT, checked_in_at TEXT)""")
    for stmt in ["ALTER TABLE visits ADD COLUMN next_visit_date TEXT", "ALTER TABLE visits ADD COLUMN inn_name TEXT",
                 "ALTER TABLE users ADD COLUMN email TEXT", "ALTER TABLE users ADD COLUMN phone TEXT",
                 "ALTER TABLE users ADD COLUMN avatar TEXT", "ALTER TABLE users ADD COLUMN region TEXT",
                 "ALTER TABLE users ADD COLUMN district TEXT", "ALTER TABLE users ADD COLUMN clinic_id TEXT",
                 "ALTER TABLE users ADD COLUMN birth_date TEXT",
                 "ALTER TABLE patients ADD COLUMN region TEXT", "ALTER TABLE patients ADD COLUMN district TEXT",
                 "ALTER TABLE patients ADD COLUMN clinic_id TEXT"]:
        try: conn.execute(stmt)
        except sqlite3.OperationalError: pass

    # --- Bootstrap / migratsiya ---
    default_clinic = conn.execute("SELECT id FROM clinics ORDER BY created_at ASC LIMIT 1").fetchone()
    if not default_clinic:
        default_clinic_id = str(uuid.uuid4())
        conn.execute("INSERT INTO clinics (id, name, created_at) VALUES (?,?,?)",
                     (default_clinic_id, "Standart klinika", datetime.datetime.utcnow().isoformat()))
    else:
        default_clinic_id = default_clinic["id"]
    # eski (clinic_id yo'q) yozuvlarni standart klinikaga biriktirib qo'yamiz
    conn.execute("UPDATE users SET clinic_id=? WHERE clinic_id IS NULL AND role != 'super_admin'", (default_clinic_id,))
    conn.execute("UPDATE patients SET clinic_id=? WHERE clinic_id IS NULL", (default_clinic_id,))
    any_user_exists = bool(conn.execute("SELECT 1 FROM users LIMIT 1").fetchone())
    has_super = bool(conn.execute("SELECT 1 FROM users WHERE role='super_admin' LIMIT 1").fetchone())
    if not has_super:
        conn.execute("INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?,?,?,?,?)",
                      (str(uuid.uuid4()), "superadmin", hash_pw("super123"), "super_admin", "Bosh super-admin"))
    # eski bazalarda "Tizim egasi" nomi "rol: Tizim egasi" bilan takrorlanib ko'rinardi — tuzatamiz
    conn.execute("UPDATE users SET full_name='Bosh super-admin' WHERE role='super_admin' AND full_name='Tizim egasi'")
    if not any_user_exists:
        conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, clinic_id) VALUES (?,?,?,?,?,?)",
                      (str(uuid.uuid4()), "admin", hash_pw("admin123"), "admin", "Bosh administrator", default_clinic_id))
    conn.commit(); conn.close()

init_db()

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
    if u["role"] != "admin": raise HTTPException(403, "Faqat klinika admini uchun")
def require_super(u):
    if u["role"] != "super_admin": raise HTTPException(403, "Faqat tizim egasi uchun")
def clinic_of(u): return u["clinic_id"]
def can_view_patient(u, patient_clinic_id, patient_id):
    if u["role"] in ("shifokor","admin"): return u["clinic_id"] == patient_clinic_id
    return u["patient_id"] == patient_id

def period_start(period):
    today = datetime.date.today()
    if period=="daily": start = today
    elif period=="weekly": start = today - datetime.timedelta(days=today.weekday())
    elif period=="monthly": start = today.replace(day=1)
    elif period=="yearly": start = today.replace(month=1, day=1)
    else: start = today - datetime.timedelta(days=3650)
    return start.isoformat()

class LoginIn(BaseModel): username: str; password: str; role: Optional[str]=None
class RegisterIn(BaseModel): full_name: str; phone: str; birth_date: Optional[str]=None; password: str; role: str
class ChangeCredentialsIn(BaseModel):
    old_password: str; new_username: Optional[str]=None; new_password: Optional[str]=None
class ProfileUpdateIn(BaseModel):
    full_name: Optional[str]=None; email: Optional[str]=None; phone: Optional[str]=None; avatar: Optional[str]=None
class ResetPasswordIn(BaseModel): username: str; phone: str; new_password: str
class ClinicIn(BaseModel): name: str; region: Optional[str]=None; district: Optional[str]=None
class ClinicAdminIn(BaseModel): username: str; password: str; full_name: str
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
class AppointmentIn(BaseModel): doctor_name: str; date: str

# ---------- Auth ----------
def login_payload(conn, user):
    token = secrets.token_hex(24)
    conn.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)", (token, user["id"], datetime.datetime.utcnow().isoformat()))
    clinic_name = None
    if user["clinic_id"]:
        c = conn.execute("SELECT name FROM clinics WHERE id=?", (user["clinic_id"],)).fetchone()
        clinic_name = c["name"] if c else None
    return {"token": token, "role": user["role"], "full_name": user["full_name"], "patient_id": user["patient_id"],
            "username": user["username"], "email": user["email"], "phone": user["phone"], "avatar": user["avatar"],
            "clinic_id": user["clinic_id"], "clinic_name": clinic_name}

@app.post("/auth/login")
def login(l: LoginIn):
    """Login sifatida foydalanuvchi nomi YOKI telefon raqam qabul qilinadi."""
    conn = get_db()
    raw = l.username.strip()
    np = normalize_phone(raw)
    rows = conn.execute("SELECT * FROM users WHERE username=? OR norm_phone(phone)=?", (raw, np or "-")).fetchall()
    pw = hash_pw(l.password)
    user = next((u for u in rows if u["password_hash"] == pw), None)
    if not user: conn.close(); raise HTTPException(401, "Login yoki parol xato")
    if l.role and user["role"] not in ROLE_GROUPS.get(l.role, ()):
        conn.close(); raise HTTPException(403, "Bu hisob tanlangan rolga mos emas. Rolni qaytadan tanlang")
    payload = login_payload(conn, user)
    conn.commit(); conn.close()
    return payload

@app.get("/auth/config")
def auth_config():
    return {"registration_open": ALLOW_SELF_REGISTRATION}

@app.post("/auth/register")
def register(r: RegisterIn):
    """VAQTINCHA (test uchun) ochiq ro'yxatdan o'tish. ALLOW_SELF_REGISTRATION=0 bilan o'chiriladi."""
    if not ALLOW_SELF_REGISTRATION:
        raise HTTPException(403, "Ro'yxatdan o'tish o'chirilgan — hisobni klinika administratoridan oling")
    if r.role not in ("bemor", "shifokor"): raise HTTPException(400, "Rol bemor yoki shifokor bo'lishi kerak")
    name = r.full_name.strip()
    if len(name) < 3: raise HTTPException(400, "Ism familiyani to'liq kiriting")
    np = normalize_phone(r.phone)
    if not np: raise HTTPException(400, "Telefon raqam noto'g'ri (+998 XX XXX XX XX)")
    if len(r.password) < 6: raise HTTPException(400, "Parol kamida 6 belgidan iborat bo'lishi kerak")
    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE username=? OR norm_phone(phone)=?", (np, np)).fetchone():
        conn.close(); raise HTTPException(400, "Bu telefon raqam bilan hisob allaqachon mavjud")
    clinic = conn.execute("SELECT id FROM clinics ORDER BY created_at ASC LIMIT 1").fetchone()
    clinic_id = clinic["id"] if clinic else None
    uid = str(uuid.uuid4()); patient_id = None; phone_store = "+" + np
    if r.role == "bemor":
        patient_id = str(uuid.uuid4())
        conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, phone, clinic_id) VALUES (?,?,?,?,?,?)",
                     (patient_id, gen_med_id(), name, r.birth_date, phone_store, clinic_id))
    conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, patient_id, phone, birth_date, clinic_id) VALUES (?,?,?,?,?,?,?,?,?)",
                 (uid, np, hash_pw(r.password), r.role, name, patient_id, phone_store, r.birth_date, clinic_id))
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    payload = login_payload(conn, user)
    conn.commit(); conn.close()
    return payload

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
    if len(body.new_password) < 6: raise HTTPException(400, "Parol kamida 6 belgidan iborat bo'lishi kerak")
    conn = get_db()
    ident = body.username.strip()
    np_ident = normalize_phone(ident)
    np_phone = normalize_phone(body.phone)
    rows = conn.execute("SELECT * FROM users WHERE username=? OR norm_phone(phone)=?", (ident, np_ident or "-")).fetchall()
    user = next((u for u in rows if np_phone and normalize_phone(u["phone"]) == np_phone), None)
    if not user: conn.close(); raise HTTPException(404, "Login yoki telefon raqam mos kelmadi")
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_pw(body.new_password), user["id"]))
    conn.commit(); conn.close()
    return {"status":"parol tiklandi"}

@app.put("/profile")
def update_profile(body: ProfileUpdateIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    for k, v in {"full_name": body.full_name, "email": body.email, "phone": body.phone, "avatar": body.avatar}.items():
        if v is not None: conn.execute(f"UPDATE users SET {k}=? WHERE id=?", (v, user["id"]))
    if body.full_name and user["patient_id"]:
        conn.execute("UPDATE patients SET full_name=? WHERE id=?", (body.full_name, user["patient_id"]))
    conn.commit(); conn.close()
    return {"status":"yangilandi"}

# ---------- SUPER ADMIN: klinikalarni boshqarish ----------
@app.get("/super/clinics")
def list_clinics(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_super(user)
    conn = get_db()
    clinics = conn.execute("SELECT * FROM clinics ORDER BY created_at ASC").fetchall()
    result = []
    for c in clinics:
        doc_count = conn.execute("SELECT COUNT(*) as n FROM users WHERE clinic_id=? AND role='shifokor'", (c["id"],)).fetchone()["n"]
        pat_count = conn.execute("SELECT COUNT(*) as n FROM patients WHERE clinic_id=?", (c["id"],)).fetchone()["n"]
        admins = conn.execute("SELECT username, full_name FROM users WHERE clinic_id=? AND role='admin'", (c["id"],)).fetchall()
        result.append({**dict(c), "doctor_count": doc_count, "patient_count": pat_count, "admins": [dict(a) for a in admins]})
    conn.close()
    return result

@app.post("/super/clinics")
def create_clinic(c: ClinicIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_super(user)
    conn = get_db(); cid = str(uuid.uuid4())
    conn.execute("INSERT INTO clinics (id, name, region, district, created_at) VALUES (?,?,?,?,?)",
                 (cid, c.name, c.region, c.district, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": cid}

@app.delete("/super/clinics/{clinic_id}")
def delete_clinic(clinic_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_super(user)
    conn = get_db()
    pids = [r["id"] for r in conn.execute("SELECT id FROM patients WHERE clinic_id=?", (clinic_id,)).fetchall()]
    for pid in pids:
        conn.execute("DELETE FROM visits WHERE patient_id=?", (pid,))
        conn.execute("DELETE FROM messages WHERE patient_id=?", (pid,))
        conn.execute("DELETE FROM ratings WHERE patient_id=?", (pid,))
    conn.execute("DELETE FROM patients WHERE clinic_id=?", (clinic_id,))
    uids = [r["id"] for r in conn.execute("SELECT id FROM users WHERE clinic_id=?", (clinic_id,)).fetchall()]
    for uid in uids:
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM support_messages WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM users WHERE clinic_id=?", (clinic_id,))
    conn.execute("DELETE FROM clinics WHERE id=?", (clinic_id,))
    conn.commit(); conn.close()
    return {"status":"o'chirildi"}

@app.post("/super/clinics/{clinic_id}/admin")
def create_clinic_admin(clinic_id: str, a: ClinicAdminIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_super(user)
    conn = get_db()
    if not conn.execute("SELECT 1 FROM clinics WHERE id=?", (clinic_id,)).fetchone():
        conn.close(); raise HTTPException(404, "Klinika topilmadi")
    if conn.execute("SELECT 1 FROM users WHERE username=?", (a.username,)).fetchone():
        conn.close(); raise HTTPException(400, "Bu foydalanuvchi nomi band")
    uid = str(uuid.uuid4())
    conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, clinic_id) VALUES (?,?,?,?,?,?)",
                 (uid, a.username, hash_pw(a.password), "admin", a.full_name, clinic_id))
    conn.commit(); conn.close()
    return {"id": uid}

# ---------- Admin: o'z klinikasi foydalanuvchilari ----------
@app.get("/admin/users")
def list_users(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_admin(user)
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, full_name, patient_id, email, phone, avatar, region, district FROM users WHERE clinic_id=?",
                         (user["clinic_id"],)).fetchall()
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
        conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor, region, district, clinic_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (patient_id, gen_med_id(), u.full_name, u.birth_date, u.gender, u.phone, u.address, u.family_doctor, u.region, u.district, user["clinic_id"]))
    conn.execute("INSERT INTO users (id, username, password_hash, role, full_name, patient_id, email, phone, region, district, clinic_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (uid, u.username, hash_pw(u.password), u.role, u.full_name, patient_id, u.email, u.phone, u.region, u.district, user["clinic_id"]))
    conn.commit(); conn.close()
    return {"id": uid, "patient_id": patient_id}

@app.put("/admin/users/{user_id}")
def edit_user(user_id: str, u: UserEditIn, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=? AND clinic_id=?", (user_id, admin["clinic_id"])).fetchone()
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
    target = conn.execute("SELECT * FROM users WHERE id=? AND clinic_id=?", (user_id, user["clinic_id"])).fetchone()
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
    user = current_user(authorization)
    conn = get_db()
    rows = conn.execute("SELECT full_name, phone, email FROM users WHERE role='shifokor' AND clinic_id=?", (user["clinic_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------- Bemorlar (klinika doirasida) ----------
@app.get("/patients")
def list_patients(q: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    if q:
        rows = conn.execute("SELECT * FROM patients WHERE clinic_id=? AND (full_name LIKE ? OR med_id LIKE ?)",
                             (user["clinic_id"], f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = conn.execute("SELECT * FROM patients WHERE clinic_id=?", (user["clinic_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/patients")
def create_patient(p: PatientIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db(); pid = str(uuid.uuid4()); med_id = gen_med_id()
    conn.execute("INSERT INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor, region, district, clinic_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (pid, med_id, p.full_name, p.birth_date, p.gender, p.phone, p.address, p.family_doctor, p.region, p.district, user["clinic_id"]))
    conn.commit(); conn.close()
    return {"id": pid, "med_id": med_id}

@app.get("/patients/{patient_id}")
def get_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient: raise HTTPException(404, "Bemor topilmadi")
    if not can_view_patient(user, patient["clinic_id"], patient_id):
        conn.close(); raise HTTPException(403, "Bu bemor sizning klinikangizga tegishli emas")
    visits = conn.execute("SELECT * FROM visits WHERE patient_id=? ORDER BY date DESC", (patient_id,)).fetchall()
    conn.close()
    result = dict(patient); result["visits"] = [dict(v) for v in visits]
    return result

@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    patient = conn.execute("SELECT clinic_id FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient or patient["clinic_id"] != user["clinic_id"]:
        conn.close(); raise HTTPException(404, "Bemor topilmadi")
    for t in ["visits","messages","ratings"]: conn.execute(f"DELETE FROM {t} WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit(); conn.close()
    return {"status":"o'chirildi"}

@app.post("/patients/{patient_id}/visits")
def add_visit(patient_id: str, v: VisitIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    patient = conn.execute("SELECT clinic_id FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient or patient["clinic_id"] != user["clinic_id"]:
        conn.close(); raise HTTPException(404, "Bemor topilmadi")
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
        WHERE patients.clinic_id=? AND visits.next_visit_date IS NOT NULL AND visits.next_visit_date != ''
        ORDER BY visits.next_visit_date ASC""", (user["clinic_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/messages/inbox")
def messages_inbox(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    rows = conn.execute("""SELECT patients.id as patient_id, patients.full_name,
        MAX(messages.created_at) as last_at,
        (SELECT body FROM messages m2 WHERE m2.patient_id = patients.id ORDER BY m2.created_at DESC LIMIT 1) as last_body
        FROM messages JOIN patients ON messages.patient_id = patients.id
        WHERE patients.clinic_id=? GROUP BY patients.id ORDER BY last_at DESC""", (user["clinic_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------- Chat (bemor kartasi bo'yicha) ----------
@app.get("/patients/{patient_id}/messages")
def get_messages(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    patient = conn.execute("SELECT clinic_id FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient or not can_view_patient(user, patient["clinic_id"], patient_id):
        conn.close(); raise HTTPException(403, "Ruxsat yo'q")
    rows = conn.execute("SELECT * FROM messages WHERE patient_id=? ORDER BY created_at ASC", (patient_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/patients/{patient_id}/messages")
def send_message(patient_id: str, m: MessageIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    patient = conn.execute("SELECT clinic_id FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient or not can_view_patient(user, patient["clinic_id"], patient_id):
        conn.close(); raise HTTPException(403, "Ruxsat yo'q")
    mid = str(uuid.uuid4())
    conn.execute("INSERT INTO messages (id, patient_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, patient_id, user["role"], user["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}

# ---------- Support chat (klinika ichida, admin bilan) ----------
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
        JOIN users ON users.id = support_messages.user_id WHERE users.clinic_id=?
        GROUP BY users.id ORDER BY last_at DESC""", (user["clinic_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/support/messages/{target_user_id}")
def support_messages_for_user(target_user_id: str, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db()
    target = conn.execute("SELECT clinic_id FROM users WHERE id=?", (target_user_id,)).fetchone()
    if not target or target["clinic_id"] != admin["clinic_id"]:
        conn.close(); raise HTTPException(403, "Bu foydalanuvchi sizning klinikangizga tegishli emas")
    rows = conn.execute("SELECT * FROM support_messages WHERE user_id=? ORDER BY created_at ASC", (target_user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/support/messages/{target_user_id}")
def admin_reply_support(target_user_id: str, m: MessageIn, authorization: Optional[str] = Header(None)):
    admin = current_user(authorization); require_admin(admin)
    conn = get_db()
    target = conn.execute("SELECT clinic_id FROM users WHERE id=?", (target_user_id,)).fetchone()
    if not target or target["clinic_id"] != admin["clinic_id"]:
        conn.close(); raise HTTPException(403, "Bu foydalanuvchi sizning klinikangizga tegishli emas")
    mid = str(uuid.uuid4())
    conn.execute("INSERT INTO support_messages (id, user_id, sender_role, sender_name, body, created_at) VALUES (?,?,?,?,?,?)",
                 (mid, target_user_id, "admin", admin["full_name"], m.body, datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": mid}

# ---------- Reyting ----------
@app.get("/patients/{patient_id}/ratings")
def get_ratings(patient_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    patient = conn.execute("SELECT clinic_id FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient or not can_view_patient(user, patient["clinic_id"], patient_id):
        conn.close(); raise HTTPException(403, "Ruxsat yo'q")
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
    vc = conn.execute("""SELECT visits.doctor, COUNT(*) as cnt FROM visits JOIN patients ON visits.patient_id = patients.id
        WHERE patients.clinic_id=? AND visits.doctor IS NOT NULL AND visits.doctor != '' GROUP BY visits.doctor""",
        (user["clinic_id"],)).fetchall()
    rr = conn.execute("""SELECT ratings.doctor_name, AVG(ratings.stars) as avg_stars, COUNT(*) as rcount
        FROM ratings JOIN patients ON ratings.patient_id = patients.id WHERE patients.clinic_id=?
        GROUP BY ratings.doctor_name""", (user["clinic_id"],)).fetchall()
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
        JOIN patients ON visits.patient_id = patients.id WHERE patients.clinic_id=? AND visits.date >= ?
        ORDER BY visits.date DESC""", (user["clinic_id"], start)).fetchall()
    top_doctors = conn.execute("""SELECT visits.doctor, COUNT(*) as cnt FROM visits JOIN patients ON visits.patient_id = patients.id
        WHERE patients.clinic_id=? AND visits.date >= ? AND visits.doctor IS NOT NULL AND visits.doctor != ''
        GROUP BY visits.doctor ORDER BY cnt DESC LIMIT 10""", (user["clinic_id"], start)).fetchall()
    total_patients = conn.execute("SELECT COUNT(*) as c FROM patients WHERE clinic_id=?", (user["clinic_id"],)).fetchone()["c"]
    total_doctors = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='shifokor' AND clinic_id=?", (user["clinic_id"],)).fetchone()["c"]
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
        JOIN patients ON visits.patient_id = patients.id WHERE patients.clinic_id=? AND visits.date >= ? AND visits.doctor = ?
        ORDER BY visits.date DESC""", (user["clinic_id"], start, user["full_name"])).fetchall()
    rating = conn.execute("""SELECT AVG(ratings.stars) as avg_stars, COUNT(*) as cnt FROM ratings
        JOIN patients ON ratings.patient_id = patients.id WHERE patients.clinic_id=? AND ratings.doctor_name=?""",
        (user["clinic_id"], user["full_name"])).fetchone()
    conn.close()
    return {"period": period, "visit_count": len(my_visits),
            "visits": [{"patient_name": v["patient_name"], "date": v["date"], "diagnosis": v["diagnosis"]} for v in my_visits],
            "avg_stars": round(rating["avg_stars"],1) if rating["avg_stars"] else None, "rating_count": rating["cnt"]}

# ---------- Navbat olish (QR bilan) ----------
@app.post("/appointments")
def book_appointment(a: AppointmentIn, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "bemor": raise HTTPException(403, "Faqat bemor navbat olishi mumkin")
    conn = get_db()
    existing = conn.execute("SELECT COUNT(*) as c FROM appointments WHERE clinic_id=? AND doctor_name=? AND date=? AND status != 'bekor qilindi'",
                             (user["clinic_id"], a.doctor_name, a.date)).fetchone()["c"]
    queue_number = existing + 1
    aid = str(uuid.uuid4())
    patient = conn.execute("SELECT full_name FROM patients WHERE id=?", (user["patient_id"],)).fetchone()
    conn.execute("""INSERT INTO appointments (id, clinic_id, patient_id, patient_name, doctor_name, date, queue_number, status, created_at)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (aid, user["clinic_id"], user["patient_id"], patient["full_name"] if patient else "", a.doctor_name, a.date,
         queue_number, "kutilmoqda", datetime.datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return {"id": aid, "queue_number": queue_number}

@app.get("/appointments/me")
def my_appointments(authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    if user["role"] != "bemor": raise HTTPException(403, "Faqat bemor uchun")
    conn = get_db()
    rows = conn.execute("SELECT * FROM appointments WHERE patient_id=? ORDER BY date DESC, queue_number ASC", (user["patient_id"],)).fetchall()
    result = []
    for r in rows:
        ahead = 0
        if r["status"] == "kutilmoqda":
            ahead = conn.execute("""SELECT COUNT(*) as c FROM appointments WHERE clinic_id=? AND doctor_name=? AND date=?
                AND status='kutilmoqda' AND queue_number < ?""", (r["clinic_id"], r["doctor_name"], r["date"], r["queue_number"])).fetchone()["c"]
        result.append({**dict(r), "ahead_count": ahead})
    conn.close()
    return result

@app.get("/appointments/today")
def appointments_today(date: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    the_date = date or datetime.date.today().isoformat()
    conn = get_db()
    if user["role"] == "shifokor":
        rows = conn.execute("SELECT * FROM appointments WHERE clinic_id=? AND date=? AND doctor_name=? ORDER BY queue_number ASC",
                             (user["clinic_id"], the_date, user["full_name"])).fetchall()
    else:
        rows = conn.execute("SELECT * FROM appointments WHERE clinic_id=? AND date=? ORDER BY doctor_name, queue_number ASC",
                             (user["clinic_id"], the_date)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/appointments/{appt_id}/checkin")
def checkin_appointment(appt_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    a = conn.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (appt_id, user["clinic_id"])).fetchone()
    if not a: raise HTTPException(404, "Navbat topilmadi")
    conn.execute("UPDATE appointments SET status='keldi', checked_in_at=? WHERE id=?", (datetime.datetime.utcnow().isoformat(), appt_id))
    conn.commit(); conn.close()
    return {"status":"keldi"}

@app.post("/appointments/{appt_id}/complete")
def complete_appointment(appt_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    a = conn.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (appt_id, user["clinic_id"])).fetchone()
    if not a: raise HTTPException(404, "Navbat topilmadi")
    conn.execute("UPDATE appointments SET status='yakunlandi' WHERE id=?", (appt_id,))
    conn.commit(); conn.close()
    return {"status":"yakunlandi"}

@app.post("/appointments/{appt_id}/cancel")
def cancel_appointment(appt_id: str, authorization: Optional[str] = Header(None)):
    user = current_user(authorization)
    conn = get_db()
    a = conn.execute("SELECT * FROM appointments WHERE id=?", (appt_id,)).fetchone()
    if not a: raise HTTPException(404, "Navbat topilmadi")
    if user["role"] == "bemor" and a["patient_id"] != user["patient_id"]: raise HTTPException(403, "Ruxsat yo'q")
    if user["role"] in ("shifokor","admin") and a["clinic_id"] != user["clinic_id"]: raise HTTPException(403, "Ruxsat yo'q")
    conn.execute("UPDATE appointments SET status='bekor qilindi' WHERE id=?", (appt_id,))
    conn.commit(); conn.close()
    return {"status":"bekor qilindi"}

# ---------- DMED (klinika doirasida) ----------
@app.get("/dmed/export")
def dmed_export(authorization: Optional[str] = Header(None)):
    user = current_user(authorization); require_staff(user)
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients WHERE clinic_id=?", (user["clinic_id"],)).fetchall()
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
        conn.execute("INSERT OR IGNORE INTO patients (id, med_id, full_name, birth_date, gender, phone, address, family_doctor, clinic_id) VALUES (?,?,?,?,?,?,?,?,?)",
                     (pid, med_id, d.get("fullName"), d.get("birthDate"), d.get("gender"), d.get("phone"), d.get("address"), d.get("familyDoctor"), user["clinic_id"]))
        for e in d.get("encounters", []):
            conn.execute("INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription, next_visit_date, inn_name) VALUES (?,?,?,?,?,?,?,?,?)",
                         (str(uuid.uuid4()), pid, e.get("date"), e.get("doctor"), e.get("complaint"), e.get("diagnosis"), e.get("prescription"), e.get("nextVisitDate"), e.get("innName")))
        added += 1
    conn.commit(); conn.close()
    return {"imported": added}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
