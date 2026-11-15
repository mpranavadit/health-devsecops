import datetime
import os
import sqlite3
import sys
import tempfile

import jwt
import pytest
from cryptography.fernet import Fernet

# --- configure environment BEFORE importing the app ---
_tmp = tempfile.mkdtemp()
PASSWORD = "Test-Pass-123!"
SECRET = "unit-test-secret-" + "x" * 32
os.environ["DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["JWT_SECRET"] = SECRET
os.environ["FIELD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["SEED_PASSWORD"] = PASSWORD

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import init_db  # noqa: E402

init_db.init()
import app as app_module  # noqa: E402


@pytest.fixture()
def client():
    return app_module.app.test_client()


def token_for(client, username, password=PASSWORD):
    resp = client.post("/login", json={"username": username, "password": password})
    return resp, resp.get_json().get("token")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    assert client.get("/health").status_code == 200


def test_login_wrong_password(client):
    resp, _ = token_for(client, "doctor1", "wrong")
    assert resp.status_code == 401


def test_login_sql_injection_attempt(client):
    resp, _ = token_for(client, "' OR '1'='1", "x")
    assert resp.status_code == 401


def test_no_token_is_401(client):
    assert client.get("/patients/1").status_code == 401


def test_expired_token_is_401(client):
    expired = jwt.encode(
        {
            "sub": "doctor1",
            "role": "doctor",
            "exp": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1),
        },
        SECRET,
        algorithm="HS256",
    )
    assert client.get("/patients/1", headers=auth(expired)).status_code == 401


def test_receptionist_cannot_read_patient(client):
    _, tok = token_for(client, "reception1")
    assert client.get("/patients/1", headers=auth(tok)).status_code == 403


def test_doctor_reads_patient_with_decrypted_diagnosis(client):
    _, tok = token_for(client, "doctor1")
    resp = client.get("/patients/1", headers=auth(tok))
    assert resp.status_code == 200
    assert resp.get_json()["diagnosis"] == "Seasonal allergy (dummy)"


def test_diagnosis_is_encrypted_in_database():
    raw = sqlite3.connect(os.environ["DB_PATH"]).execute(
        "SELECT diagnosis_enc FROM patients WHERE id = 1"
    ).fetchone()[0]
    assert "allergy" not in raw.lower()


def test_receptionist_can_book_appointment(client):
    _, tok = token_for(client, "reception1")
    resp = client.post(
        "/appointments",
        headers=auth(tok),
        json={"patient_id": 1, "scheduled_for": "2030-01-15 10:30", "reason": "checkup"},
    )
    assert resp.status_code == 201
    assert client.get("/appointments", headers=auth(tok)).status_code == 200


def test_invalid_appointment_date_rejected(client):
    _, tok = token_for(client, "doctor1")
    resp = client.post(
        "/appointments", headers=auth(tok), json={"patient_id": 1, "scheduled_for": "tomorrow"}
    )
    assert resp.status_code == 400


def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
