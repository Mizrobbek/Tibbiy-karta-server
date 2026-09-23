"""
Elektron Tibbiy Karta — REST API
Oilaviy poliklinika uchun. FastAPI + SQLite asosida.

O'RNATISH:
    pip install fastapi uvicorn --break-system-packages
    uvicorn tibbiy_karta_api:app --reload --port 8000

Ishga tushgach:
    http://127.0.0.1:8000/docs   -> avtomatik interaktiv API hujjatlari (Swagger)

Frontend (tibbiy-karta.html) bilan bog'lash uchun, HTML fayldagi `db` obyekti
ichidagi localStorage chaqiruvlarini quyidagi endpointlarga fetch() qiling.

DMED BILAN ULASH:
    /dmed/export  — barcha bemorlarni DMED kutayotgan JSON sxemasida qaytaradi
    /dmed/import  — DMED'dan kelgan JSON'ni shu bazaga yozadi
    Haqiqiy DMED integratsiyasida bu ikki endpoint o'rniga Sog'liqni saqlash
    vazirligi/Uzinfocom bergan rasmiy API shartnomasi (autentifikatsiya turi,
    aniq maydon nomlari, almashinuv chastotasi) qo'llaniladi — bu fayl shu
    ulanishni tez join qilish uchun tayyor "moslashtiruvchi qatlam" vazifasini
    o'taydi.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, uuid, random, datetime, os

DB_PATH = "tibbiy_karta.db"
app = FastAPI(title="Elektron Tibbiy Karta API", version="1.0")

# Frontend (Netlify saytingiz) shu APIga so'rov yubora olishi uchun.
# Ishlab chiqarishga chiqarganda "*" o'rniga aniq domeningizni yozish tavsiya etiladi,
# masalan: ["https://tibbi-karta.netlify.app"]
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY,
            med_id TEXT UNIQUE,
            full_name TEXT NOT NULL,
            birth_date TEXT,
            gender TEXT,
            phone TEXT,
            address TEXT,
            family_doctor TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS visits (
            id TEXT PRIMARY KEY,
            patient_id TEXT NOT NULL,
            date TEXT,
            doctor TEXT,
            complaint TEXT,
            diagnosis TEXT,
            prescription TEXT,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        )
    """)
    conn.commit()
    conn.close()


init_db()


def gen_med_id() -> str:
    return f"UZ-MED-{random.randint(10**11, 10**12 - 1)}"


# ---------- Sxema (Pydantic) ----------

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


# ---------- Bemorlar ----------

@app.get("/patients")
def list_patients(q: Optional[str] = None):
    """Barcha bemorlar ro'yxati. ?q= bilan ism yoki MED-ID bo'yicha qidirish."""
    conn = get_db()
    if q:
        rows = conn.execute(
            "SELECT * FROM patients WHERE full_name LIKE ? OR med_id LIKE ?",
            (f"%{q}%", f"%{q}%")
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM patients").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/patients")
def create_patient(p: PatientIn):
    """Yangi bemor qo'shadi va avtomatik MED-ID beradi."""
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
def get_patient(patient_id: str):
    """Bitta bemorning to'liq tibbiy kartasi (ma'lumot + barcha tashriflar)."""
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient:
        raise HTTPException(404, "Bemor topilmadi")
    visits = conn.execute(
        "SELECT * FROM visits WHERE patient_id=? ORDER BY date DESC", (patient_id,)
    ).fetchall()
    conn.close()
    result = dict(patient)
    result["visits"] = [dict(v) for v in visits]
    return result


@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: str):
    conn = get_db()
    conn.execute("DELETE FROM visits WHERE patient_id=?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    conn.commit()
    conn.close()
    return {"status": "o'chirildi"}


# ---------- Tashriflar ----------

@app.post("/patients/{patient_id}/visits")
def add_visit(patient_id: str, v: VisitIn):
    """Bemor kartasiga yangi tashrif (qabul) yozadi."""
    conn = get_db()
    exists = conn.execute("SELECT 1 FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not exists:
        raise HTTPException(404, "Bemor topilmadi")
    vid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (vid, patient_id, v.date, v.doctor, v.complaint, v.diagnosis, v.prescription)
    )
    conn.commit()
    conn.close()
    return {"id": vid}


# ---------- DMED bilan almashish ----------

@app.get("/dmed/export")
def dmed_export():
    """Barcha bazani DMED kutayotgan umumiy JSON sxemasida qaytaradi."""
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
                "diagnosis": v["diagnosis"], "prescription": v["prescription"]
            } for v in visits]
        })
    conn.close()
    return result


@app.post("/dmed/import")
def dmed_import(payload: dict):
    """DMED'dan yoki boshqa tizimdan kelgan bemorlar ro'yxatini bazaga yozadi."""
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
                "INSERT INTO visits (id, patient_id, date, doctor, complaint, diagnosis, prescription) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), pid, e.get("date"), e.get("doctor"), e.get("complaint"),
                 e.get("diagnosis"), e.get("prescription"))
            )
        added += 1
    conn.commit()
    conn.close()
    return {"imported": added}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
