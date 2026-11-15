"""Create tables and seed DUMMY data. Safe to run on every container start."""
import os
import sqlite3

import bcrypt
from cryptography.fernet import Fernet

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('doctor', 'receptionist', 'admin'))
);
CREATE TABLE IF NOT EXISTS patients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    dob           TEXT NOT NULL,
    diagnosis_enc TEXT NOT NULL            -- encrypted at application level (Fernet)
);
CREATE TABLE IF NOT EXISTS appointments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id    INTEGER NOT NULL REFERENCES patients(id),
    scheduled_for TEXT NOT NULL,
    reason        TEXT,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

DUMMY_USERS = [
    ("doctor1", "doctor"),
    ("reception1", "receptionist"),
    ("admin1", "admin"),
]

DUMMY_PATIENTS = [
    ("Test Patient One", "1990-01-15", "Seasonal allergy (dummy)"),
    ("Test Patient Two", "1985-06-30", "Type 2 diabetes (dummy)"),
    ("Test Patient Three", "1978-11-02", "Hypertension (dummy)"),
]


def init():
    db_path = os.environ.get("DB_PATH", "/data/health.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.executescript(SCHEMA)

        seed_password = os.environ.get("SEED_PASSWORD", "")
        if seed_password and conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            pw_hash = bcrypt.hashpw(seed_password.encode()[:72], bcrypt.gensalt()).decode()
            conn.executemany(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                [(u, pw_hash, r) for u, r in DUMMY_USERS],
            )

        key = os.environ.get("FIELD_ENCRYPTION_KEY", "")
        if key and conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0] == 0:
            f = Fernet(key.encode())
            conn.executemany(
                "INSERT INTO patients (name, dob, diagnosis_enc) VALUES (?, ?, ?)",
                [(n, d, f.encrypt(dx.encode()).decode()) for n, d, dx in DUMMY_PATIENTS],
            )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init()
