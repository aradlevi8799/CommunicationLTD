"""
app_vulnerable.py – גרסה פגיעה (חלק ב' – הדגמת התקפות)

⚠️  קובץ זה נועד לצרכי לימוד בלבד!
    הוא מדגים שתי פרצות אבטחה קלאסיות:

    פרצה 1 – SQL Injection (SQLi)
    ===============================
    בגרסה הפגיעה, שאילתות SQL בנויות בשרשור מחרוזות:
        query = "SELECT * FROM users WHERE username = '" + username + "'"
    תוקף יכול להזין:  admin' --
    התוצאה:           SELECT * FROM users WHERE username = 'admin' --'
    ה-- מבטל את שאר השאילתה → כניסה ללא סיסמא!

    פרצה 2 – Stored XSS (Cross-Site Scripting)
    =============================================
    בגרסה הפגיעה, שם הלקוח נשמר כמו שהוא ומוצג ללא קידוד:
        {{ customer.name | safe }}   ← מסמן את הערך כ"בטוח" ועוקף Jinja2
    תוקף יכול להזין:  <script>alert('XSS')</script>
    בכל פעם שדף זה ייטען – הסקריפט יורץ אצל כל המשתמשים!
"""

import json
import sqlite3

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


# ─────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# סעיף 1: Register – VULNERABLE to SQLi
# ─────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email    = request.form.get("email", "")

        valid, error_msg = validate_password(password, config)
        if not valid:
            flash(error_msg, "error")
            return render_template("register.html")

        pw_hash, salt = hash_password(password)

        conn = sqlite3.connect(DB_PATH)
        try:
            # ⚠️ VULNERABLE: שרשור מחרוזות – SQLi אפשרי!
            # קלט זדוני: username = "hacker', 'fakehash', 'fakesalt', 'h@h.com'); --"
            query = (
                f"INSERT INTO users (username, password_hash, salt, email) "
                f"VALUES ('{username}', '{pw_hash}', '{salt}', '{email}')"
            )
            conn.execute(query)
            conn.commit()
            flash("נרשמת בהצלחה!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"שגיאה: {e}", "error")
        finally:
            conn.close()

    return render_template("register.html")


# ─────────────────────────────────────────────
# סעיף 3: Login – VULNERABLE to SQLi
# ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        # ⚠️ VULNERABLE: שרשור מחרוזות – SQLi קלאסי!
        #
        # קלט זדוני לעקיפת Login:
        #   username = "' OR '1'='1' --"
        #   שאילתה: SELECT * FROM users WHERE username = '' OR '1'='1' --'
        #   תוצאה: '1'='1' תמיד נכון → מחזיר את כל המשתמשים!
        #
        # כיצד עובד ה-bypass:
        #   כאשר ה-SQL מחזיר שורה (גם ללא username תקין),
        #   והשם שהוזן שונה מהשם האמיתי במסד → האפליקציה מזהה injection
        #   ומאפשרת כניסה ללא בדיקת סיסמא (כפי שאפליקציות פגיעות נאיביות עושות).
        query = f"SELECT * FROM users WHERE username = '{username}'"
        users = conn.execute(query).fetchall()
        conn.close()

        if not users:
            flash("שם משתמש או סיסמא שגויים", "error")
            return render_template("login.html")

        user = users[0]

        if user["locked"]:
            flash("החשבון נעול", "error")
            return render_template("login.html")

        # ⚠️ SQLi BYPASS: אם הוחזרו מספר שורות, או ששם המשתמש שהוזן
        # שונה מהשם האמיתי (סימן לinjection) – כניסה ללא בדיקת סיסמא!
        if len(users) > 1 or username.strip() != user["username"]:
            session["username"] = user["username"]
            flash(f"[SQLi] נכנסת כ-{user['username']} ללא סיסמא!", "warning")
            return redirect(url_for("system"))

        # זרימה רגילה – בדיקת סיסמא
        if verify_password(password, user["password_hash"], user["salt"]):
            with get_db() as c:
                c.execute("UPDATE users SET failed_login_attempts = 0 WHERE username = ?", (username,))
            session["username"] = username
            return redirect(url_for("system"))

        new_attempts = user["failed_login_attempts"] + 1
        max_attempts = config["security"]["max_login_attempts"]
        locked       = 1 if new_attempts >= max_attempts else 0
        with get_db() as c:
            c.execute(
                "UPDATE users SET failed_login_attempts = ?, locked = ? WHERE username = ?",
                (new_attempts, locked, username),
            )
        if locked:
            flash("החשבון ננעל", "error")
        else:
            flash("שם משתמש או סיסמא שגויים", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# סעיף 2: Change Password (זהה לגרסה מאובטחת)
# ─────────────────────────────────────────────

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        username   = session["username"]

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

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


# ─────────────────────────────────────────────
# סעיף 5: Forgot Password (זהה לגרסה מאובטחת)
# ─────────────────────────────────────────────

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user:
            token = generate_reset_token()
            with get_db() as conn:
                conn.execute("INSERT INTO reset_tokens (username, token) VALUES (?, ?)", (username, token))
            sent = send_reset_email(user["email"], token, config)
            if not sent:
                flash(f"[פיתוח] קוד האיפוס: {token}", "info")
            else:
                flash("קוד איפוס נשלח למייל שלך", "success")
        else:
            flash("אם המשתמש קיים, קוד איפוס יישלח למייל", "success")

        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token  = request.form.get("token", "").strip()
        new_pw = request.form.get("new_password", "")

        with get_db() as conn:
            reset = conn.execute("SELECT * FROM reset_tokens WHERE token = ? AND used = 0", (token,)).fetchone()

        if not reset:
            flash("קוד איפוס לא תקין", "error")
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


# ─────────────────────────────────────────────
# סעיף 4: System – VULNERABLE to Stored XSS + SQLi
# ─────────────────────────────────────────────

@app.route("/system", methods=["GET", "POST"])
def system():
    if "username" not in session:
        return redirect(url_for("login"))

    new_customer_name = None

    if request.method == "POST":
        name    = request.form.get("name", "")   # ⚠️ ללא strip() או escape()
        email   = request.form.get("email", "")
        phone   = request.form.get("phone", "")
        package = request.form.get("package", "")

        conn = sqlite3.connect(DB_PATH)
        try:
            # ⚠️ VULNERABLE: שרשור מחרוזות – SQLi + Stored XSS!
            # קלט זדוני לXSS:   name = "<script>document.cookie</script>"
            # קלט זדוני לSQLi:  name = "test', 'x','x','x','x'); DROP TABLE customers; --"
            query = (
                f"INSERT INTO customers (name, email, phone, package) "
                f"VALUES ('{name}', '{email}', '{phone}', '{package}')"
            )
            conn.execute(query)
            conn.commit()

            # ⚠️ שם הלקוח נשמר ללא קידוד – יוצג כ-HTML גולמי בתבנית
            new_customer_name = name
            flash("לקוח חדש נוסף!", "success")
        except Exception as e:
            flash(f"שגיאה: {e}", "error")
        finally:
            conn.close()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    customers = conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    conn.close()

    return render_template(
        "system.html",
        customers=customers,
        new_customer_name=new_customer_name,
        version="vulnerable",  # התבנית תציג את השם ללא קידוד
    )


# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("!! מפעיל גרסה פגיעה על http://127.0.0.1:5001")
    print("!! קובץ זה לצרכי לימוד בלבד – לא לפרוס בסביבת ייצור!")
    app.run(debug=True, port=5001)
