"""
utils.py – Shared helper functions for both app versions.
"""

import hmac
import hashlib
import json
import re
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def load_config() -> dict:
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)


def hash_password(password: str) -> tuple[str, str]:
    """Returns (password_hash, salt). Uses HMAC-SHA256 with a random 32-byte salt."""
    salt = secrets.token_hex(32)  # 64 hex chars = 256 bits of entropy
    h = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256)
    return h.hexdigest(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Uses compare_digest to prevent timing attacks during hash comparison."""
    h = hmac.new(salt.encode("utf-8"), password.encode("utf-8"), hashlib.sha256)
    return hmac.compare_digest(h.hexdigest(), stored_hash)


def validate_password(password: str, config: dict) -> tuple[bool, str]:
    """Validates password against all rules in config.json. Returns (is_valid, error_message)."""
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
    """Returns True if new_password matches any entry in history (reuse is forbidden)."""
    for old_hash, old_salt in history:
        if verify_password(new_password, old_hash, old_salt):
            return True
    return False


def generate_reset_token() -> str:
    """Generates a random value hashed with SHA-1, as specified by the project requirements."""
    random_bytes = secrets.token_bytes(32)          # 256 random bits
    return hashlib.sha1(random_bytes).hexdigest()   # SHA-1 as per spec


def send_reset_email(to_email: str, token: str, config: dict) -> bool:
    """Sends a password-reset email. Returns False and logs the error if sending fails."""
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
