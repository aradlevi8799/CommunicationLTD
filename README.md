# CommunicationLTD – פרויקט סיום קורס סייבר
**מגישים:
**
תומר בן בשט- 207017542
רום בן יקר - 207295437
שרון וייסמן- 208660456
בר סברו - 314683665

מערכת ווב לחברת תקשורת דמיונית, שנבנתה כעבודת גמר בקורס אבטחת מחשבים.  
הפרויקט מדגים גם **פיתוח מאובטח** וגם **התקפות אבטחה קלאסיות** (SQLi + XSS) – בשתי גרסאות נפרדות.

---

## מה יש כאן?

| קובץ | תיאור |
|---|---|
| `app_secure.py` | גרסה מאובטחת – port 5000 |
| `app_vulnerable.py` | גרסה פגיעה להדגמת התקפות – port 5001 |
| `config.json` | מדיניות סיסמאות (ניתן לשינוי ע"י מנהל) |
| `utils.py` | פונקציות עזר: HMAC-SHA256, SHA-1, בדיקת מדיניות |
| `init_db.py` | יצירת/איפוס מסד הנתונים SQLite |
| `templates/` | דפי HTML בעברית (RTL) |
| `test_project.py` | 95 בדיקות אוטומטיות |
| `הסבר_מלא.md` / `.pdf` | מדריך מלא למתחילים |

---

## הרצה מהירה

```bash
# התקנת תלויות
pip install -r requirements.txt

# יצירת מסד הנתונים
python init_db.py

# גרסה מאובטחת
python app_secure.py
# → http://127.0.0.1:5000

# גרסה פגיעה (בטרמינל נפרד)
python app_vulnerable.py
# → http://127.0.0.1:5001
```

---

## חלק א' – פיתוח מאובטח (`app_secure.py`)

| סעיף | מסך | הגנות מיושמות |
|---|---|---|
| 1 | Register | HMAC-SHA256 + Salt, מדיניות סיסמא מ-config.json |
| 2 | שינוי סיסמא | אימות סיסמא נוכחית, היסטוריית 3 סיסמאות |
| 3 | Login | הודעה גנרית, נעילה אחרי 3 כישלונות, compare_digest |
| 4 | System | Parameterized Queries, html.escape + Jinja2 autoescaping |
| 5 | שכח סיסמא | טוקן SHA-1 אקראי, שליחה למייל, שימוש חד-פעמי |

---

## חלק ב' – התקפות והגנות (`app_vulnerable.py`)

| התקפה | איפה | הגנה בגרסה המאובטחת |
|---|---|---|
| SQL Injection | Register + Login + Forgot Password + System | Parameterized Queries (`?`) |
| Stored XSS | System (הוספת לקוח) | Jinja2 autoescaping + `html.escape()` |

### הדגמת SQLi ב-Login (port 5001):
```
שדה username:  ' OR '1'='1' --
שדה password:  כל דבר
תוצאה: כניסה ללא סיסמא!
```

### הדגמת Stored XSS ב-System (port 5001):
```
שדה שם לקוח:  <script>alert(1)</script>
תוצאה: הסקריפט יורץ אצל כל מי שפותח את הדף
```

---

## קובץ קונפיגורציה (`config.json`)

```json
{
  "password_policy": {
    "min_length": 10,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digits": true,
    "require_special": true,
    "history_count": 3,
    "dictionary": ["password", "123456789", ...]
  },
  "security": {
    "max_login_attempts": 3
  }
}
```

---

## הרצת בדיקות

```bash
# ודא ששני השרתים רצים, ואז:
python test_project.py
# → 95/95 בדיקות עוברות
```

---

## מסד הנתונים

SQLite – נוצר אוטומטית ע"י `init_db.py`.  
3 טבלאות: `users`, `customers`, `reset_tokens`.  
הקובץ `communication_ltd.db` לא נכלל ב-repo (מוחרג ב-`.gitignore`).
