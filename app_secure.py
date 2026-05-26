"""
app_secure.py – Secure version (Part A + Part B fixes).

Protections implemented:
  - Parameterized queries (no SQL injection)
  - Jinja2 autoescaping (no XSS)
  - HMAC-SHA256 + random salt (passwords never stored in plain text)
  - Password policy enforced from config.json
  - Password history: last 3 passwords blocked from reuse
  - Login attempt limit with account lockout
  - compare_digest to prevent timing attacks
"""

import json
import sqlite3
from html import escape

from flask import Flask, flash, redirect, render_template, request, session, url_for

from init_db import init_db
from utils import (
    check_password_history,
    generate_reset_token,
    hash_password,
    load_config,
    send_reset_email,
    validate_password,
    verify_password,
)

app = Flask(__name__)
config = load_config()
app.secret_key = config["security"]["secret_key"]

DB_PATH = "communication_ltd.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return redirect(url_for("login"))


# ── Register ──────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip()

        if not username or not password or not email:
            flash("יש למלא את כל השדות", "error")
            return render_template("register.html")

        valid, error_msg = validate_password(password, config)
        if not valid:
            flash(error_msg, "error")
            return render_template("register.html")

        pw_hash, salt = hash_password(password)

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, email) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, salt, email),
                )
            flash("נרשמת בהצלחה! אנא התחבר.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("שם המשתמש כבר קיים, בחר שם אחר", "error")

    return render_template("register.html")


# ── Login ─────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user is None:
            # Generic message avoids revealing whether the username exists
            flash("שם משתמש או סיסמא שגויים", "error")
            return render_template("login.html")

        if user["locked"]:
            flash("החשבון נעול עקב יותר מדי ניסיונות כושלים. צור קשר עם המנהל.", "error")
            return render_template("login.html")

        if verify_password(password, user["password_hash"], user["salt"]):
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET failed_login_attempts = 0 WHERE username = ?",
                    (username,),
                )
            session["username"] = username
            return redirect(url_for("system"))

        new_attempts = user["failed_login_attempts"] + 1
        max_attempts = config["security"]["max_login_attempts"]
        locked       = 1 if new_attempts >= max_attempts else 0

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET failed_login_attempts = ?, locked = ? WHERE username = ?",
                (new_attempts, locked, username),
            )

        if locked:
            flash("החשבון ננעל עקב יותר מדי ניסיונות כושלים", "error")
        else:
            flash("שם משתמש או סיסמא שגויים", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


# ── Change Password ───────────────────────────────────────

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        username   = session["username"]

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if not verify_password(current_pw, user["password_hash"], user["salt"]):
            flash("הסיסמא הנוכחית שגויה", "error")
            return render_template("change_password.html")

        valid, error_msg = validate_password(new_pw, config)
        if not valid:
            flash(error_msg, "error")
            return render_template("change_password.html")

        history = json.loads(user["password_history"])
        if check_password_history(new_pw, history):
            n = config["password_policy"]["history_count"]
            flash(f"לא ניתן להשתמש באחת מ-{n} הסיסמאות האחרונות", "error")
            return render_template("change_password.html")

        # Push current password into history before replacing it
        history.append([user["password_hash"], user["salt"]])
        history = history[-config["password_policy"]["history_count"]:]

        new_hash, new_salt = hash_password(new_pw)

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, salt = ?, password_history = ? WHERE username = ?",
                (new_hash, new_salt, json.dumps(history), username),
            )

        flash("הסיסמא שונתה בהצלחה!", "success")
        return redirect(url_for("system"))

    return render_template("change_password.html")


# ── Forgot Password ───────────────────────────────────────

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user:
            token = generate_reset_token()

            with get_db() as conn:
                conn.execute(
                    "INSERT INTO reset_tokens (username, token) VALUES (?, ?)",
                    (username, token),
                )

            sent = send_reset_email(user["email"], token, config)
            if not sent:
                # Dev fallback: display token on screen when SMTP is not configured
                flash(f"[פיתוח] קוד האיפוס: {token}", "info")
            else:
                flash("קוד איפוס נשלח למייל שלך", "success")
        else:
            # Generic message to prevent username enumeration
            flash("אם המשתמש קיים, קוד איפוס יישלח למייל", "success")

        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token  = request.form.get("token", "").strip()
        new_pw = request.form.get("new_password", "")

        with get_db() as conn:
            reset = conn.execute(
                "SELECT * FROM reset_tokens WHERE token = ? AND used = 0", (token,)
            ).fetchone()

        if not reset:
            flash("קוד איפוס לא תקין או שכבר נוצל", "error")
            return render_template("reset_password.html")

        valid, error_msg = validate_password(new_pw, config)
        if not valid:
            flash(error_msg, "error")
            return render_template("reset_password.html")

        new_hash, new_salt = hash_password(new_pw)
        username = reset["username"]

        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, salt = ?, failed_login_attempts = 0, locked = 0 WHERE username = ?",
                (new_hash, new_salt, username),
            )
            conn.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))

        flash("הסיסמא אופסה בהצלחה!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ── System – Add Customer ─────────────────────────────────

@app.route("/system", methods=["GET", "POST"])
def system():
    if "username" not in session:
        return redirect(url_for("login"))

    new_customer_name = None

    if request.method == "POST":
        name    = request.form.get("name", "").strip()
        email   = request.form.get("email", "").strip()
        phone   = request.form.get("phone", "").strip()
        package = request.form.get("package", "").strip()

        if not name:
            flash("שם הלקוח הוא שדה חובה", "error")
        else:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO customers (name, email, phone, package) VALUES (?, ?, ?, ?)",
                    (name, email, phone, package),
                )
            # escape() is an extra defense layer; Jinja2 autoescaping also handles this in the template
            new_customer_name = escape(name)
            flash(f'לקוח חדש נוסף בהצלחה!', "success")

    with get_db() as conn:
        customers = conn.execute(
            "SELECT * FROM customers ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "system.html",
        customers=customers,
        new_customer_name=new_customer_name,
        version="secure",
    )


if __name__ == "__main__":
    init_db()
    print("OK - מפעיל גרסה מאובטחת על http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
