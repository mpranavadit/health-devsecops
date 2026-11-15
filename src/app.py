"""Patient Appointment API - DevSecOps demo.

DUMMY DATA ONLY. Never load real patient data into this demo system.

Security features:
  * bcrypt password hashing, short-lived JWT with role claim
  * role-based access control (doctor / receptionist / admin)
  * parameterised SQL everywhere (no SQL injection)
  * diagnosis field encrypted at rest (Fernet)
  * audit log for logins, PHI access and denied requests
  * security response headers, request size limit, JSON error handlers
  * secrets only from environment variables (injected from Kubernetes Secrets)
"""
import datetime
import logging
import os
import sqlite3
from functools import wraps

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

DB_PATH = os.environ.get("DB_PATH", "/data/health.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
FIELD_KEY = os.environ.get("FIELD_ENCRYPTION_KEY", "")
TOKEN_MINUTES = 15

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be set and at least 32 characters long")
if not FIELD_KEY:
    raise RuntimeError("FIELD_ENCRYPTION_KEY must be set (Fernet key)")
fernet = Fernet(FIELD_KEY.encode())

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
audit = logging.getLogger("AUDIT")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # reject large request bodies

# Used so that unknown usernames cost the same time as wrong passwords.
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


# ----------------------------------------------------------------- helpers
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def decrypt(value):
    try:
        return fernet.decrypt(value.encode()).decode()
    except InvalidToken:
        return "[unreadable]"


def require_role(*roles):
    """Allow the request only if it carries a valid JWT with one of `roles`."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="missing bearer token"), 401
            try:
                claims = jwt.decode(
                    header[7:],
                    JWT_SECRET,
                    algorithms=["HS256"],
                    options={"require": ["exp", "sub", "role"]},
                )
            except jwt.PyJWTError:
                audit.warning("AUTH_FAIL path=%s ip=%s", request.path, request.remote_addr)
                return jsonify(error="invalid or expired token"), 401
            if claims["role"] not in roles:
                audit.warning(
                    "DENIED user=%r role=%s path=%s", claims["sub"], claims["role"], request.path
                )
                return jsonify(error="forbidden"), 403
            g.user = claims
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ----------------------------------------------------------- HTTP hardening
@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(HTTPException)
def handle_http_error(err):
    return jsonify(error=err.name), err.code


@app.errorhandler(Exception)
def handle_unexpected(err):
    app.logger.exception("unhandled error: %s", err)
    return jsonify(error="internal server error"), 500


# ------------------------------------------------------------------ routes
@app.get("/")
def index():
    return jsonify(service="health-api", status="running")


@app.get("/health")
def health():
    return "ok", 200


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))[:64]
    password = str(data.get("password", "")).encode()[:72]

    row = get_db().execute(
        "SELECT password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    stored = row["password_hash"].encode() if row else _DUMMY_HASH
    valid = bcrypt.checkpw(password, stored)

    if not row or not valid:
        audit.warning("LOGIN_FAIL user=%r ip=%s", username, request.remote_addr)
        return jsonify(error="invalid credentials"), 401

    now = datetime.datetime.now(datetime.timezone.utc)
    token = jwt.encode(
        {
            "sub": username,
            "role": row["role"],
            "iat": now,
            "exp": now + datetime.timedelta(minutes=TOKEN_MINUTES),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    audit.info("LOGIN_OK user=%r role=%s ip=%s", username, row["role"], request.remote_addr)
    return jsonify(token=token, expires_in_minutes=TOKEN_MINUTES)


@app.get("/patients/<int:pid>")
@require_role("doctor", "admin")
def get_patient(pid):
    row = get_db().execute(
        "SELECT id, name, dob, diagnosis_enc FROM patients WHERE id = ?", (pid,)
    ).fetchone()
    audit.info("PHI_ACCESS user=%r patient=%s found=%s", g.user["sub"], pid, row is not None)
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(
        id=row["id"], name=row["name"], dob=row["dob"], diagnosis=decrypt(row["diagnosis_enc"])
    )


@app.post("/appointments")
@require_role("receptionist", "doctor", "admin")
def create_appointment():
    data = request.get_json(silent=True) or {}
    try:
        patient_id = int(data["patient_id"])
        when = datetime.datetime.strptime(str(data["scheduled_for"]), "%Y-%m-%d %H:%M")
    except (KeyError, ValueError, TypeError):
        return jsonify(error="patient_id (int) and scheduled_for ('YYYY-MM-DD HH:MM') required"), 400
    reason = str(data.get("reason", ""))[:200]

    db = get_db()
    if db.execute("SELECT 1 FROM patients WHERE id = ?", (patient_id,)).fetchone() is None:
        return jsonify(error="patient not found"), 404
    cur = db.execute(
        "INSERT INTO appointments (patient_id, scheduled_for, reason, created_by) "
        "VALUES (?, ?, ?, ?)",
        (patient_id, when.strftime("%Y-%m-%d %H:%M"), reason, g.user["sub"]),
    )
    db.commit()
    audit.info("APPT_CREATED user=%r appointment=%s patient=%s", g.user["sub"], cur.lastrowid, patient_id)
    return jsonify(id=cur.lastrowid), 201


@app.get("/appointments")
@require_role("receptionist", "doctor", "admin")
def list_appointments():
    rows = get_db().execute(
        "SELECT id, patient_id, scheduled_for, reason, created_by "
        "FROM appointments ORDER BY id DESC LIMIT 50"
    ).fetchall()
    audit.info("APPT_LIST user=%r count=%s", g.user["sub"], len(rows))
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    # Local development only. In containers gunicorn serves the app on port 8000.
    app.run(host="127.0.0.1", port=8000)
