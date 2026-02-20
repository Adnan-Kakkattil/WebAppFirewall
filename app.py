import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from typing import Optional
from urllib.parse import unquote_plus

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "waf.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET", "change-this-secret")

ATTACK_PATTERNS = {
    "SQLi": [
        re.compile(r"\b(select|union|drop|insert|delete|update|where|or)\b", re.IGNORECASE),
        re.compile(r"('|\"|\-\-|\#|;)\s*(or|and)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
        re.compile(r"\bunion\s+select\b", re.IGNORECASE),
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
    ],
    "XSS": [
        re.compile(r"<\s*script\b", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
    ],
    "PathTraversal": [
        re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
        re.compile(r"%2e%2e%2f|%2e%2e%5c", re.IGNORECASE),
    ],
    "CommandInjection": [
        re.compile(r"(\||;|&&)\s*(cat|ls|whoami|id|wget|curl|powershell|cmd)\b", re.IGNORECASE),
    ],
}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL,
            attack_type TEXT
        )
        """
    )
    db.commit()
    ensure_default_admin()


def ensure_default_admin():
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if not username or not password:
        return
    password_hash = generate_password_hash(password)
    db = get_db()
    existing = db.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
    if existing is None:
        db.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_count() -> int:
    db = get_db()
    return db.execute("SELECT COUNT(*) AS total FROM admins").fetchone()["total"]


def collect_payload() -> str:
    pieces = []
    for key, value in request.args.items():
        pieces.append(f"{key}={value}")
    for key, value in request.form.items():
        pieces.append(f"{key}={value}")
    if request.is_json:
        body = request.get_json(silent=True)
        if body is not None:
            pieces.append(str(body))
    raw_body = request.get_data(cache=True, as_text=True)
    if raw_body:
        pieces.append(raw_body)
    return " | ".join(pieces).strip()


def detect_attack(payload: str):
    if not payload:
        return None
    decoded_payload = unquote_plus(payload)
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(decoded_payload):
                return attack_type
    return None


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_attack(attack_type: str, payload: str):
    db = get_db()
    db.execute(
        """
        INSERT INTO attacks (timestamp, ip_address, attack_type, payload, path, method)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(timespec="seconds"),
            get_client_ip(),
            attack_type,
            payload[:5000],
            request.path,
            request.method,
        ),
    )
    db.commit()


def log_request(status: str, payload: str, attack_type: Optional[str] = None):
    db = get_db()
    db.execute(
        """
        INSERT INTO request_logs (timestamp, ip_address, method, path, payload, status, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(timespec="seconds"),
            get_client_ip(),
            request.method,
            request.path,
            payload[:5000],
            status,
            attack_type,
        ),
    )
    db.commit()


@app.before_request
def waf_layer():
    if request.path.startswith("/static"):
        return None

    # Avoid scanning admin credential submissions to reduce false positives.
    if request.path in {
        "/admin/login",
        "/admin/setup",
        "/admin/users/create",
        "/admin/users/delete",
        "/admin/users/reset-password",
    }:
        return None

    payload = collect_payload()
    attack_type = detect_attack(payload)

    if attack_type:
        log_request(status="BLOCKED", payload=payload, attack_type=attack_type)
        log_attack(attack_type, payload)
        return (
            render_template(
                "blocked.html",
                attack_type=attack_type,
                blocked_payload=payload,
                page_title="Request Blocked",
                active_nav="overview",
            ),
            403,
        )
    log_request(status="ALLOWED", payload=payload, attack_type=None)
    return None


@app.route("/")
def home():
    db = get_db()
    traffic_total = db.execute("SELECT COUNT(*) AS total FROM request_logs").fetchone()["total"]
    blocked_total = db.execute(
        "SELECT COUNT(*) AS total FROM request_logs WHERE status = 'BLOCKED'"
    ).fetchone()["total"]
    allowed_total = db.execute(
        "SELECT COUNT(*) AS total FROM request_logs WHERE status = 'ALLOWED'"
    ).fetchone()["total"]
    sqli_total = db.execute(
        "SELECT COUNT(*) AS total FROM attacks WHERE attack_type = 'SQLi'"
    ).fetchone()["total"]
    xss_total = db.execute(
        "SELECT COUNT(*) AS total FROM attacks WHERE attack_type = 'XSS'"
    ).fetchone()["total"]
    stats = {
        "traffic": traffic_total,
        "allowed": allowed_total,
        "blocked": blocked_total,
        "sqli": sqli_total,
        "xss": xss_total,
    }
    return render_template(
        "index.html", page_title="Security Overview", active_nav="overview", stats=stats
    )


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    return render_template(
        "simulate.html",
        query=query,
        source="search",
        page_title="Attack Simulator",
        active_nav="simulator",
    )


@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    payload = ""
    if request.method == "POST":
        payload = request.form.get("payload", "")
        flash("Payload allowed by WAF. Try common attack strings to test blocking.")
    return render_template(
        "simulate.html",
        query=payload,
        source="simulate",
        page_title="Attack Simulator",
        active_nav="simulator",
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if admin_count() == 0:
        return redirect(url_for("admin_setup"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        admin = db.execute(
            "SELECT id, username, password_hash FROM admins WHERE username = ?",
            (username,),
        ).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session["admin_logged_in"] = True
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect(url_for("admin_dashboard"))
        flash("Invalid username or password.")
    return render_template("admin_login.html", page_title="Admin Login")


@app.route("/admin/setup", methods=["GET", "POST"])
def admin_setup():
    if admin_count() > 0:
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters.")
            return render_template("admin_setup.html", page_title="Admin Setup")
        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("admin_setup.html", page_title="Admin Setup")
        if password != confirm_password:
            flash("Password confirmation does not match.")
            return render_template("admin_setup.html", page_title="Admin Setup")

        db = get_db()
        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        flash("Admin account created. Please sign in.")
        return redirect(url_for("admin_login"))

    return render_template("admin_setup.html", page_title="Admin Setup")


@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    attacks = db.execute(
        """
        SELECT timestamp, ip_address, attack_type, payload, path, method
        FROM attacks
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    summary = db.execute(
        "SELECT attack_type, COUNT(*) AS total FROM attacks GROUP BY attack_type ORDER BY total DESC"
    ).fetchall()
    requests = db.execute(
        """
        SELECT timestamp, ip_address, method, path, status, attack_type
        FROM request_logs
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    admins = db.execute(
        """
        SELECT id, username
        FROM admins
        ORDER BY username ASC
        """
    ).fetchall()
    traffic_total = db.execute("SELECT COUNT(*) AS total FROM request_logs").fetchone()["total"]
    blocked_total = db.execute(
        "SELECT COUNT(*) AS total FROM request_logs WHERE status = 'BLOCKED'"
    ).fetchone()["total"]
    allowed_total = db.execute(
        "SELECT COUNT(*) AS total FROM request_logs WHERE status = 'ALLOWED'"
    ).fetchone()["total"]
    sqli_total = db.execute(
        "SELECT COUNT(*) AS total FROM attacks WHERE attack_type = 'SQLi'"
    ).fetchone()["total"]
    xss_total = db.execute(
        "SELECT COUNT(*) AS total FROM attacks WHERE attack_type = 'XSS'"
    ).fetchone()["total"]

    stats = {
        "traffic": traffic_total,
        "allowed": allowed_total,
        "blocked": blocked_total,
        "sqli": sqli_total,
        "xss": xss_total,
    }
    return render_template(
        "admin_dashboard.html",
        attacks=attacks,
        requests=requests,
        admins=admins,
        current_admin_id=session.get("admin_id"),
        summary=summary,
        stats=stats,
        page_title="Security Logs",
        active_nav="logs",
    )


@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(username) < 3:
        flash("New admin username must be at least 3 characters.")
        return redirect(url_for("admin_dashboard"))
    if len(password) < 8:
        flash("New admin password must be at least 8 characters.")
        return redirect(url_for("admin_dashboard"))
    if password != confirm_password:
        flash("New admin password confirmation does not match.")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    exists = db.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
    if exists:
        flash("Admin username already exists.")
        return redirect(url_for("admin_dashboard"))

    db.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
        (username, generate_password_hash(password)),
    )
    db.commit()
    flash("New admin user created successfully.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/reset-password", methods=["POST"])
@admin_required
def admin_reset_password():
    admin_id = request.form.get("admin_id", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not admin_id.isdigit():
        flash("Invalid admin selected for password reset.")
        return redirect(url_for("admin_dashboard"))
    if len(password) < 8:
        flash("Reset password must be at least 8 characters.")
        return redirect(url_for("admin_dashboard"))
    if password != confirm_password:
        flash("Reset password confirmation does not match.")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    admin = db.execute("SELECT id FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if not admin:
        flash("Admin user not found.")
        return redirect(url_for("admin_dashboard"))

    db.execute(
        "UPDATE admins SET password_hash = ? WHERE id = ?",
        (generate_password_hash(password), admin_id),
    )
    db.commit()
    flash("Admin password reset successfully.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    admin_id = request.form.get("admin_id", "").strip()
    current_admin_id = session.get("admin_id")

    if not admin_id.isdigit():
        flash("Invalid admin selected for deletion.")
        return redirect(url_for("admin_dashboard"))
    if current_admin_id and str(current_admin_id) == admin_id:
        flash("You cannot delete your own logged-in admin account.")
        return redirect(url_for("admin_dashboard"))

    if admin_count() <= 1:
        flash("Cannot delete the last remaining admin account.")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    admin = db.execute("SELECT id FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if not admin:
        flash("Admin user not found.")
        return redirect(url_for("admin_dashboard"))

    db.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    db.commit()
    flash("Admin user deleted successfully.")
    return redirect(url_for("admin_dashboard"))


@app.errorhandler(403)
def forbidden(_error):
    return (
        render_template(
            "blocked.html",
            attack_type="Suspicious Input",
            blocked_payload="",
            page_title="Request Blocked",
            active_nav="overview",
        ),
        403,
    )


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
