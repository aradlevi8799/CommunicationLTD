"""
init_db.py – יוצר את מסד הנתונים SQLite עם כל הטבלאות הדרושות.
הרץ קובץ זה פעם אחת לפני שמפעילים את האפליקציה.
"""
import sqlite3

DB_PATH = "communication_ltd.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executescript("""
        DROP TABLE IF EXISTS reset_tokens;
        DROP TABLE IF EXISTS customers;
        DROP TABLE IF EXISTS users;

        -- טבלת משתמשים
        CREATE TABLE IF NOT EXISTS users (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            username              TEXT UNIQUE NOT NULL,
            password_hash         TEXT NOT NULL,
            salt                  TEXT NOT NULL,
            email                 TEXT NOT NULL,
            -- היסטוריית סיסמאות: JSON של [[hash, salt], ...]
            password_history      TEXT DEFAULT '[]',
            failed_login_attempts INTEGER DEFAULT 0,
            locked                INTEGER DEFAULT 0
        );

        -- טבלת לקוחות (חלק א' סעיף 4)
        CREATE TABLE IF NOT EXISTS customers (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT,
            phone      TEXT,
            package    TEXT
        );

        -- טבלת טוקנים לאיפוס סיסמא (חלק א' סעיף 5)
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            token      TEXT NOT NULL,
            used       INTEGER DEFAULT 0
        );
    """)

    conn.commit()
    conn.close()
    print("OK - DB created:", DB_PATH)


if __name__ == "__main__":
    init_db()
