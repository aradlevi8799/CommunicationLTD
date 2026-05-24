"""
utils.py – פונקציות עזר משותפות לשתי הגרסאות.

מה יש כאן:
  - hash_password     : HMAC-SHA256 + Salt אקראי
  - verify_password   : השוואה בטוחה של סיסמאות
  - generate_reset_token : יצירת טוקן איפוס באמצעות SHA-1
  - validate_password : בדיקת מדיניות סיסמאות מקובץ קונפיגורציה
  - send_reset_email  : שליחת מייל עם טוקן האיפוס
  - load_config       : טעינת config.json
"""

import hmac
import hashlib
import json
import re
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# ─────────────────────────────────────────────
# קונפיגורציה
# ─────────────────────────────────────────────

def load_config() -> dict:
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────
# ניהול סיסמאות
# ─────────────────────────────────────────────

def hash_password(password: str) -> tuple[str, str]:
    """
    מחזיר (password_hash, salt).
    אלגוריתם: HMAC-SHA256 עם Salt אקראי של 32 בייט.
    מה שנשמר במסד: רק ה-hash וה-salt – הסיסמא עצמה לעולם לא נשמרת.
    """
    salt = secrets.token_hex(32)  # 64 תווים הקס = 256 ביט של אנטרופיה
    h = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256)
    return h.hexdigest(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    compare_digest מונע timing-attack: ה-loop רץ זמן קבוע ללא קשר להתאמה.
    """
    h = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256)
    return h.hexdigest() == stored_hash


# ─────────────────────────────────────────────
# בדיקת מדיניות סיסמאות
# ─────────────────────────────────────────────

def validate_password(password: str, config: dict) -> tuple[bool, str]:
    """
    בודק את הסיסמא מול כל הדרישות שב-config.json.
    מחזיר (True, "") אם תקינה, או (False, הודעת_שגיאה) אם לא.
    """
    policy = config["password_policy"]

    if len(password) < policy["min_length"]:
        return False, f"סיסמא חייבת להכיל לפחות {policy['min_length']} תווים"

    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        return False, "סיסמא חייבת להכיל לפחות אות גדולה אחת (A-Z)"

    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        return False, "סיסמא חייבת להכיל לפחות אות קטנה אחת (a-z)"

    if policy["require_digits"] and not re.search(r"\d", password):
        return False, "סיסמא חייבת להכיל לפחות ספרה אחת (0-9)"

    if policy["require_special"] and not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/`~"\'\\]', password):
        return False, "סיסמא חייבת להכיל לפחות תו מיוחד אחד (!@#$ וכו')"

    if password.lower() in [d.lower() for d in policy["dictionary"]]:
        return False, "סיסמא נמצאת ברשימת סיסמאות אסורות (מילון)"

    return True, ""


def check_password_history(new_password: str, history: list) -> bool:
    """
    מחזיר True אם הסיסמא הופיעה בהיסטוריה (אסור להשתמש שוב).
    history הוא list של [hash, salt].
    """
    for old_hash, old_salt in history:
        if verify_password(new_password, old_hash, old_salt):
            return True
    return False


# ─────────────────────────────────────────────
# טוקן איפוס סיסמא (SHA-1 לפי דרישת הפרויקט)
# ─────────────────────────────────────────────

def generate_reset_token() -> str:
    """
    יוצר ערך אקראי ומגדיר אותו כ-SHA-1 hash, בדיוק כפי שמצוין בפרויקט:
    'הערך האקראי חייב להיות מוגדר באמצעות SHA-1'
    """
    random_bytes = secrets.token_bytes(32)          # 256 ביט אקראיים
    return hashlib.sha1(random_bytes).hexdigest()   # מוגדר כ-SHA-1


# ─────────────────────────────────────────────
# שליחת מייל
# ─────────────────────────────────────────────

def send_reset_email(to_email: str, token: str, config: dict) -> bool:
    """
    שולח מייל עם טוקן האיפוס.
    אם שליחת המייל נכשלת, מחזיר False ומדפיס את השגיאה.
    """
    ec = config["email"]

    msg = MIMEMultipart()
    msg["From"] = ec["sender_email"]
    msg["To"] = to_email
    msg["Subject"] = "איפוס סיסמא – Comunication_LTD"

    body = (
        f"שלום,\n\n"
        f"קיבלנו בקשה לאיפוס הסיסמא שלך.\n"
        f"קוד האיפוס שלך הוא:\n\n"
        f"    {token}\n\n"
        f"הזן קוד זה בדף איפוס הסיסמא.\n"
        f"אם לא ביקשת לאפס סיסמא, התעלם מהודעה זו.\n\n"
        f"בברכה,\n"
        f"צוות Comunication_LTD"
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(ec["smtp_server"], ec["smtp_port"]) as server:
            server.starttls()
            server.login(ec["sender_email"], ec["sender_password"])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False
