"""
test_project.py – Comprehensive tests for the CommunicationLTD project.
Covers all requirements from Part A and Part B.
"""

import sys
import json
import requests

# reset DB at start of every test run so results are reproducible
from init_db import init_db
init_db()

SECURE  = "http://127.0.0.1:5000"
VULN    = "http://127.0.0.1:5001"

PASS    = "[PASS]"
FAIL    = "[FAIL]"
SECTION = "=" * 60

results = []


def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    line = f"  {status} {name}"
    if detail:
        line += f"\n         >> {detail}"
    results.append((condition, name))
    print(line)
    return condition


def section(title):
    print(f"\n{SECTION}")
    print(f"  {title}")
    print(SECTION)


def new_session():
    s = requests.Session()
    s.max_redirects = 5
    return s


# ──────────────────────────────────────────────────────────
# CONFIG.JSON
# ──────────────────────────────────────────────────────────

section("CONFIG.JSON - מדיניות סיסמאות")

with open("config.json", encoding="utf-8") as f:
    cfg = json.load(f)

pol = cfg["password_policy"]
sec = cfg["security"]

check("min_length = 10",           pol["min_length"] == 10)
check("require_uppercase = true",  pol["require_uppercase"] is True)
check("require_lowercase = true",  pol["require_lowercase"] is True)
check("require_digits = true",     pol["require_digits"] is True)
check("require_special = true",    pol["require_special"] is True)
check("history_count = 3",         pol["history_count"] == 3)
check("dictionary לא ריק",         len(pol["dictionary"]) > 0)
check("max_login_attempts = 3",    sec["max_login_attempts"] == 3)
check("secret_key קיים",           len(sec.get("secret_key","")) > 10)
check("email config קיים",        "email" in cfg)

# ──────────────────────────────────────────────────────────
# UTILS.PY - בדיקות פנימיות
# ──────────────────────────────────────────────────────────

section("UTILS.PY - פונקציות hash ואימות")

import sys, os
sys.path.insert(0, os.getcwd())
from utils import hash_password, verify_password, generate_reset_token, validate_password, check_password_history

h1, s1 = hash_password("Test@12345")
check("hash_password מחזיר (hash, salt)",   bool(h1) and bool(s1))
check("hash לא שווה לסיסמא המקורית",        h1 != "Test@12345")
check("salt אקראי (64 תווים)",              len(s1) == 64)

check("verify_password - סיסמא נכונה",      verify_password("Test@12345", h1, s1))
check("verify_password - סיסמא שגויה",      not verify_password("WrongPass!", h1, s1))

h2, s2 = hash_password("Test@12345")
check("שני hash שונים לאותה סיסמא (Salt!)",  h1 != h2)

token = generate_reset_token()
check("generate_reset_token מחזיר 40 תווים (SHA-1)", len(token) == 40)
check("token הקסדצימלי בלבד",               all(c in "0123456789abcdef" for c in token))
t2 = generate_reset_token()
check("כל token שונה (אקראיות)",             token != t2)

section("UTILS.PY - validate_password")

ok, _ = validate_password("Test@12345",  cfg); check("סיסמא תקינה עוברת",     ok)
ok, _ = validate_password("short1A!",   cfg); check("קצרה מדי (< 10) נדחית", not ok)
ok, _ = validate_password("nouppercase1!", cfg); check("ללא אות גדולה נדחית",  not ok)
ok, _ = validate_password("NOLOWER1!AA", cfg); check("ללא אות קטנה נדחית",   not ok)
ok, _ = validate_password("NoDigitsHere!", cfg); check("ללא ספרה נדחית",      not ok)
ok, _ = validate_password("NoSpecial123ABC", cfg); check("ללא תו מיוחד נדחית", not ok)
ok, _ = validate_password("password",   cfg); check("סיסמא ממילון נדחית",     not ok)

section("UTILS.PY - היסטוריית סיסמאות")

h_old, s_old = hash_password("OldPass@99")
history = [[h_old, s_old]]
check("סיסמא ישנה נמצאת בהיסטוריה",    check_password_history("OldPass@99", history))
check("סיסמא חדשה לא בהיסטוריה",       not check_password_history("NewPass@11", history))


# ──────────────────────────────────────────────────────────
# חלק א' - SECURE SERVER (port 5000)
# ──────────────────────────────────────────────────────────

section("חלק א' - סעיף 1: REGISTER (secure)")

s = new_session()

# דף register נטען
r = s.get(f"{SECURE}/register")
check("דף /register נטען (200)", r.status_code == 200)
check("מכיל שדה username", 'name="username"' in r.text)
check("מכיל שדה password", 'name="password"' in r.text)
check("מכיל שדה email",    'name="email"' in r.text)

# הרשמה עם סיסמא חלשה מדי
r = s.post(f"{SECURE}/register",
    data={"username": "testuser", "password": "weak", "email": "t@t.com"},
    allow_redirects=True)
check("סיסמא חלשה מדחית בהרשמה", "200" in str(r.status_code) and "error" in r.text.lower() or "חייבת" in r.text)

# הרשמה תקינה
r = s.post(f"{SECURE}/register",
    data={"username": "testuser_sec", "password": "SecurePass@99", "email": "test@test.com"},
    allow_redirects=True)
check("הרשמה תקינה מצליחה", r.status_code == 200 and ("התחב" in r.text or "login" in r.url.lower() or "נרשמת" in r.text))

# הרשמה כפולה נדחית
r = s.post(f"{SECURE}/register",
    data={"username": "testuser_sec", "password": "SecurePass@99", "email": "test@test.com"},
    allow_redirects=True)
check("הרשמה כפולה נדחית", "קיים" in r.text or "error" in r.text.lower())

# בדיקת Hash במסד
import sqlite3
conn = sqlite3.connect("communication_ltd.db")
conn.row_factory = sqlite3.Row
user = conn.execute("SELECT * FROM users WHERE username = ?", ("testuser_sec",)).fetchone()
check("משתמש נשמר במסד", user is not None)
if user:
    check("password_hash קיים (לא ריק)",  bool(user["password_hash"]))
    check("salt קיים (לא ריק)",           bool(user["salt"]))
    check("הסיסמא לא נשמרה בטקסט פשוט",   user["password_hash"] != "SecurePass@99")
    check("email נשמר",                   user["email"] == "test@test.com")
conn.close()

section("חלק א' - סעיף 3: LOGIN (secure)")

# Login עם פרטים שגויים
s = new_session()
r = s.post(f"{SECURE}/login",
    data={"username": "testuser_sec", "password": "WrongPass@11"},
    allow_redirects=True)
check("סיסמא שגויה מוחזרת הודעה גנרית (לא מגלה אם קיים)", "שגויים" in r.text or "error" in r.text.lower())
check("סיסמא שגויה לא מתחברת",  "system" not in r.url.lower())

# Login מוצלח
s = new_session()
r = s.post(f"{SECURE}/login",
    data={"username": "testuser_sec", "password": "SecurePass@99"},
    allow_redirects=True)
check("Login מוצלח מגיע ל-system", "system" in r.url.lower() or "לקוח" in r.text or "system" in r.text.lower())

# נעילה אחרי 3 כישלונות
s_lock = new_session()
s_lock.post(f"{SECURE}/register",
    data={"username": "locktest", "password": "SecurePass@99", "email": "l@l.com"},
    allow_redirects=True)
for _ in range(3):
    s_lock.post(f"{SECURE}/login",
        data={"username": "locktest", "password": "WrongPass@11"},
        allow_redirects=True)
r = s_lock.post(f"{SECURE}/login",
    data={"username": "locktest", "password": "WrongPass@11"},
    allow_redirects=True)
check("חשבון ננעל אחרי 3 כישלונות", "נעול" in r.text or "locked" in r.text.lower())

conn = sqlite3.connect("communication_ltd.db")
conn.row_factory = sqlite3.Row
u = conn.execute("SELECT * FROM users WHERE username = ?", ("locktest",)).fetchone()
check("locked=1 נשמר במסד",  u is not None and u["locked"] == 1)
conn.close()

section("חלק א' - סעיף 2: CHANGE PASSWORD (secure)")

s = new_session()
s.post(f"{SECURE}/register",
    data={"username": "changetest", "password": "OldPass@12!", "email": "c@c.com"},
    allow_redirects=True)
s.post(f"{SECURE}/login",
    data={"username": "changetest", "password": "OldPass@12!"},
    allow_redirects=True)

r = s.get(f"{SECURE}/change_password")
check("דף שינוי סיסמא נטען", r.status_code == 200 and "current_password" in r.text)

# סיסמא נוכחית שגויה
r = s.post(f"{SECURE}/change_password",
    data={"current_password": "WrongOld@12!", "new_password": "NewPass@12!"},
    allow_redirects=True)
check("סיסמא נוכחית שגויה נדחית", "שגויה" in r.text or "error" in r.text.lower())

# החלפה תקינה
r = s.post(f"{SECURE}/change_password",
    data={"current_password": "OldPass@12!", "new_password": "NewPass@12!"},
    allow_redirects=True)
check("שינוי סיסמא תקין מצליח", "שונתה" in r.text or "success" in r.text.lower() or r.status_code == 200)

# אי אפשר לחזור לסיסמא ישנה (היסטוריה)
r = s.post(f"{SECURE}/change_password",
    data={"current_password": "NewPass@12!", "new_password": "OldPass@12!"},
    allow_redirects=True)
check("סיסמא ישנה מהיסטוריה נדחית", "אחרונות" in r.text or "היסטור" in r.text or "error" in r.text.lower())

section("חלק א' - סעיף 5: FORGOT PASSWORD (secure)")

# רישום משתמש עם מייל
s2 = new_session()
s2.post(f"{SECURE}/register",
    data={"username": "forgottest", "password": "ForgotPass@1", "email": "forgot@test.com"},
    allow_redirects=True)

r = s2.get(f"{SECURE}/forgot_password")
check("דף שכח סיסמא נטען", r.status_code == 200)

r = s2.post(f"{SECURE}/forgot_password",
    data={"username": "forgottest"},
    allow_redirects=True)
check("שכח סיסמא לא נותן שגיאה", r.status_code == 200)

# בדיקת token במסד
conn = sqlite3.connect("communication_ltd.db")
conn.row_factory = sqlite3.Row
token_row = conn.execute(
    "SELECT * FROM reset_tokens WHERE username = ? AND used = 0 ORDER BY id DESC",
    ("forgottest",)).fetchone()
check("token נוצר במסד", token_row is not None)
if token_row:
    tok = token_row["token"]
    check("token הוא SHA-1 (40 תווים הקס)", len(tok) == 40 and all(c in "0123456789abcdef" for c in tok))

    # שימוש בtoken לאיפוס
    r = s2.get(f"{SECURE}/reset_password")
    check("דף reset_password נטען", r.status_code == 200)

    r = s2.post(f"{SECURE}/reset_password",
        data={"token": tok, "new_password": "ResetPass@1"},
        allow_redirects=True)
    check("איפוס סיסמא עם token תקין מצליח", "אופסה" in r.text or "success" in r.text.lower() or "login" in r.url.lower())

    # token לא ניתן לשימוש פעמיים
    r = s2.post(f"{SECURE}/reset_password",
        data={"token": tok, "new_password": "ResetPass@2"},
        allow_redirects=True)
    check("token שנוצל לא ניתן לשימוש שוב", "תקין" not in r.text or "לא תקין" in r.text or "error" in r.text.lower() or "נוצל" in r.text)

conn.close()

section("חלק א' - סעיף 4: SYSTEM (secure)")

s3 = new_session()
s3.post(f"{SECURE}/register",
    data={"username": "sysuser", "password": "SysPass@12!", "email": "sys@test.com"},
    allow_redirects=True)
s3.post(f"{SECURE}/login",
    data={"username": "sysuser", "password": "SysPass@12!"},
    allow_redirects=True)

r = s3.get(f"{SECURE}/system")
check("דף system נטען", r.status_code == 200)

# הוספת לקוח
r = s3.post(f"{SECURE}/system",
    data={"name": "ישראל ישראלי", "email": "isr@test.com", "phone": "050-1234567", "package": "premium"},
    allow_redirects=True)
check("הוספת לקוח תקינה מצליחה", "ישראל ישראלי" in r.text or "נוסף" in r.text)

conn = sqlite3.connect("communication_ltd.db")
cust = conn.execute("SELECT * FROM customers WHERE name = ?", ("ישראל ישראלי",)).fetchone()
check("לקוח נשמר במסד", cust is not None)
conn.close()

# ──────────────────────────────────────────────────────────
# חלק ב' - VULNERABLE SERVER (port 5001)
# ──────────────────────────────────────────────────────────

section("חלק ב' - SQLi ב-LOGIN (סעיף 3, port 5001)")

# רישום משתמש לגיטימי לגרסה פגיעה
sv = new_session()
sv.post(f"{VULN}/register",
    data={"username": "legituser", "password": "LegitPass@1!", "email": "leg@leg.com"},
    allow_redirects=True)

# ניסיון SQLi ב-Login
sv2 = new_session()
r = sv2.post(f"{VULN}/login",
    data={"username": "' OR '1'='1' --", "password": "anything"},
    allow_redirects=True)
sqli_login_works = "system" in r.url.lower() or "SQLi" in r.text or "נכנסת" in r.text or "warning" in r.text.lower()
check("SQLi ב-Login מצליח לעקוף אימות (גרסה פגיעה)", sqli_login_works,
      f"URL: {r.url}")

section("חלק ב' - SQLi ב-REGISTER (סעיף 1, port 5001)")

sv3 = new_session()
r = sv3.post(f"{VULN}/register",
    data={"username": "sqli_reg_test", "password": "RegPass@123!", "email": "r@r.com"},
    allow_redirects=True)
check("Register פגיע לא קורס על קלט רגיל", r.status_code == 200)

# אימות שה-query מורכב בשרשור
import inspect, app_vulnerable as av
src = inspect.getsource(av.register)
check("register פגיע משתמש בשרשור מחרוזות (f-string)",
      "f\"INSERT" in src or "f'INSERT" in src or "+ username +" in src or "VALUES ('" in src)

section("חלק ב' - SQLi ב-SYSTEM (סעיף 4, port 5001)")

# Login לגרסה פגיעה
sv4 = new_session()
sv4.post(f"{VULN}/login",
    data={"username": "legituser", "password": "LegitPass@1!"},
    allow_redirects=True)

# הוספת לקוח – אימות שה-query פגיע לשרשור
src_sys = inspect.getsource(av.system)
check("system פגיע משתמש בשרשור מחרוזות",
      "f\"INSERT" in src_sys or "VALUES ('" in src_sys)

# הוספת לקוח תקין
r = sv4.post(f"{VULN}/system",
    data={"name": "VulnCustomer", "email": "v@v.com", "phone": "050-9999999", "package": "basic"},
    allow_redirects=True)
check("הוספת לקוח לגיטימי מצליחה בגרסה פגיעה", "VulnCustomer" in r.text or "נוסף" in r.text)

section("חלק ב' - Stored XSS ב-SYSTEM (סעיף 4, port 5001)")

import app_secure as asec
src_sec_sys = inspect.getsource(asec.system)
src_vuln_sys = inspect.getsource(av.system)

# אימות שהגרסה הפגיעה מחזירה | safe ב-template
with open("templates/system.html", encoding="utf-8") as f:
    tmpl = f.read()
check("templates/system.html קיים ומכיל לוגיקת version", "version" in tmpl)

# אימות שהגרסה הפגיעה שולחת version='vulnerable'
check("app_vulnerable מעביר version='vulnerable' ל-template",
      "vulnerable" in src_vuln_sys)
check("app_secure מעביר version='secure' ל-template",
      "secure" in src_sec_sys)

# בדיקת XSS בתגובת הגרסה הפגיעה
xss_payload = "<script>alert(1)</script>"
sv5 = new_session()
sv5.post(f"{VULN}/login",
    data={"username": "legituser", "password": "LegitPass@1!"},
    allow_redirects=True)
r = sv5.post(f"{VULN}/system",
    data={"name": xss_payload, "email": "x@x.com", "phone": "050", "package": "basic"},
    allow_redirects=True)
check("XSS payload נשמר ומוצג ללא קידוד (גרסה פגיעה)",
      xss_payload in r.text,
      f"payload בתגובה: {'כן' if xss_payload in r.text else 'לא'}")

section("חלק ב' - הגנות ב-SECURE SERVER")

# XSS מוגן – Jinja2 escaping
s5 = new_session()
s5.post(f"{SECURE}/register",
    data={"username": "xsstest", "password": "XssPass@12!", "email": "xss@xss.com"},
    allow_redirects=True)
s5.post(f"{SECURE}/login",
    data={"username": "xsstest", "password": "XssPass@12!"},
    allow_redirects=True)
r = s5.post(f"{SECURE}/system",
    data={"name": xss_payload, "email": "x@x.com", "phone": "050", "package": "basic"},
    allow_redirects=True)
check("XSS payload מקודד בגרסה המאובטחת (לא מוצג כ-HTML גולמי)",
      xss_payload not in r.text,
      f"payload חי בתגובה: {'כן (BAD)' if xss_payload in r.text else 'לא (GOOD)'}")
check("תווי < > מקודדים ל-&lt; &gt;",
      "&lt;script&gt;" in r.text or "alert" not in r.text)

# SQLi מוגן – Parameterized Queries
s6 = new_session()
r = s6.post(f"{SECURE}/login",
    data={"username": "' OR '1'='1' --", "password": "anything"},
    allow_redirects=True)
check("SQLi ב-Login חסום בגרסה המאובטחת",
      "system" not in r.url.lower() and "SQLi" not in r.text)

# אימות Parameterized Queries בקוד
import app_secure as asec
src_sec_reg  = inspect.getsource(asec.register)
src_sec_log  = inspect.getsource(asec.login)
src_sec_sys2 = inspect.getsource(asec.system)

check("Register מאובטח משתמש ב-? (Parameterized)",
      '"?"' in src_sec_reg or "?, ?, ?, ?" in src_sec_reg or "(?, ?, ?, ?)" in src_sec_reg)
check("Login מאובטח משתמש ב-? (Parameterized)",
      "WHERE username = ?" in src_sec_log)
check("System מאובטח משתמש ב-? (Parameterized)",
      "(?, ?, ?, ?)" in src_sec_sys2 or "?, ?, ?, ?" in src_sec_sys2)
check("app_secure מייבא html.escape",
      "from html import escape" in inspect.getsource(asec))

# ──────────────────────────────────────────────────────────
# HMAC implementation verification
# ──────────────────────────────────────────────────────────

section("UTILS.PY - HMAC implementation verification")

import hmac as _hmac_mod
import hashlib as _hl_mod

h_test, s_test = hash_password("SamePass@1!")
# Recompute manually to confirm the stored hash really comes from HMAC-SHA256
expected_hmac = _hmac_mod.new(s_test.encode(), "SamePass@1!".encode(), _hl_mod.sha256).hexdigest()
check("Stored hash matches manual HMAC-SHA256 recomputation", expected_hmac == h_test)
check("hash_password source code uses hmac.new", "hmac.new" in inspect.getsource(hash_password))

# ──────────────────────────────────────────────────────────
# Dictionary attack prevention – all configured entries
# ──────────────────────────────────────────────────────────

section("Password policy - dictionary attack prevention (all entries)")

for dict_pw in cfg["password_policy"]["dictionary"]:
    ok, _ = validate_password(dict_pw, cfg)
    check(f"Dictionary entry '{dict_pw}' rejected", not ok)

# ──────────────────────────────────────────────────────────
# Password history – full 3-rotation cycle
# ──────────────────────────────────────────────────────────

section("Password history - full 3-rotation cycle")

s_hist = new_session()
s_hist.post(f"{SECURE}/register",
    data={"username": "histcycle", "password": "Cycle0@AA!", "email": "cycle@test.com"},
    allow_redirects=True)
s_hist.post(f"{SECURE}/login",
    data={"username": "histcycle", "password": "Cycle0@AA!"},
    allow_redirects=True)

# Perform 4 consecutive password changes to push the original (AA) out of the
# 3-entry history. The history stores the last 3 OLD passwords (current is not
# included), so after 4 rotations the original AA is no longer tracked.
for old_pw, new_pw in [
    ("Cycle0@AA!", "Cycle0@BB!"),
    ("Cycle0@BB!", "Cycle0@CC!"),
    ("Cycle0@CC!", "Cycle0@DD!"),
    ("Cycle0@DD!", "Cycle0@EE!"),
]:
    s_hist.post(f"{SECURE}/change_password",
        data={"current_password": old_pw, "new_password": new_pw},
        allow_redirects=True)

# AA is no longer in the last-3 history; it must be accepted again
r = s_hist.post(f"{SECURE}/change_password",
    data={"current_password": "Cycle0@EE!", "new_password": "Cycle0@AA!"},
    allow_redirects=True)
check("Password allowed after rotating out of history window",
      "שונתה" in r.text or "success" in r.text.lower())

# CC, DD, EE are still in history – reusing DD must be blocked
s_hist.post(f"{SECURE}/login",
    data={"username": "histcycle", "password": "Cycle0@AA!"},
    allow_redirects=True)
r = s_hist.post(f"{SECURE}/change_password",
    data={"current_password": "Cycle0@AA!", "new_password": "Cycle0@DD!"},
    allow_redirects=True)
check("Recently used password still blocked after subsequent changes",
      "אחרונות" in r.text or "היסטור" in r.text or "error" in r.text.lower())

# ──────────────────────────────────────────────────────────
# Unauthenticated access protection
# ──────────────────────────────────────────────────────────

section("Unauthenticated access protection (secure)")

s_noauth = new_session()
r_sys = s_noauth.get(f"{SECURE}/system", allow_redirects=False)
check("/system redirects unauthenticated users (302)", r_sys.status_code == 302)

r_cp = s_noauth.get(f"{SECURE}/change_password", allow_redirects=False)
check("/change_password redirects unauthenticated users (302)", r_cp.status_code == 302)

# ──────────────────────────────────────────────────────────
# Forgot password – username enumeration prevention
# ──────────────────────────────────────────────────────────

section("Forgot password - username enumeration prevention")

s_enum = new_session()
r = s_enum.post(f"{SECURE}/forgot_password",
    data={"username": "nonexistent_user_xyz_0001"},
    allow_redirects=True)
check("Non-existent user gets 200 with generic message (no error)", r.status_code == 200)
check("Response does not reveal that user does not exist",
      "לא קיים" not in r.text and "not found" not in r.text.lower())

# ──────────────────────────────────────────────────────────
# SQLi in forgot_password – vulnerable version
# ──────────────────────────────────────────────────────────

section("חלק ב' - SQLi ב-FORGOT PASSWORD (סעיף 5, port 5001)")

src_vuln_fp = inspect.getsource(av.forgot_password)
check("forgot_password פגיע משתמש בשרשור מחרוזות (f-string)",
      "f\"SELECT" in src_vuln_fp or "f'SELECT" in src_vuln_fp
      or "WHERE username = '" in src_vuln_fp)

src_sec_fp = inspect.getsource(asec.forgot_password)
check("forgot_password מאובטח משתמש ב-? (Parameterized)",
      "WHERE username = ?" in src_sec_fp)

# ──────────────────────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────────────────────

passed = sum(1 for ok, _ in results if ok)
failed = sum(1 for ok, _ in results if not ok)
total  = len(results)

print(f"\n{SECTION}")
print(f"  סיכום: {passed}/{total} בדיקות עברו")
print(SECTION)
if failed > 0:
    print(f"\n  בדיקות שנכשלו ({failed}):")
    for ok, name in results:
        if not ok:
            print(f"    [FAIL] {name}")
else:
    print("\n  כל הבדיקות עברו בהצלחה!")

print()
sys.exit(0 if failed == 0 else 1)
