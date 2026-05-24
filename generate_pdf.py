"""
generate_pdf.py – ממיר את הסבר_מלא.md ל-PDF עם תמיכה מלאה ב-RTL עברית.
משתמש ב-Microsoft Edge Headless לקבלת רינדור מושלם.
"""

import io
import os
import subprocess
import tempfile

import markdown

# ── קריאת קובץ Markdown ──
with open("הסבר_מלא.md", "r", encoding="utf-8") as f:
    md_text = f.read()

# ── המרה ל-HTML ──
html_body = markdown.markdown(
    md_text,
    extensions=["tables", "fenced_code"],
)

# ── HTML מלא עם CSS RTL מושלם ──
full_html = """<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <style>
    /* ── בסיס ── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      direction: rtl;
      text-align: right;
      font-size: 11pt;
      line-height: 1.75;
      color: #1a202c;
      padding: 0 10px;
    }

    /* ── מרווחי הדפסה ── */
    @media print {
      @page {
        margin: 2cm 2cm 2cm 2cm;
        size: A4;
      }
      pre, table, .no-break { page-break-inside: avoid; }
      h1, h2, h3, h4 { page-break-after: avoid; }
    }

    /* ── כותרות ── */
    h1 {
      font-size: 22pt;
      font-weight: 700;
      color: #1a365d;
      border-bottom: 3px solid #3182ce;
      padding-bottom: 8px;
      margin: 20px 0 10px 0;
    }

    h2 {
      font-size: 16pt;
      font-weight: 700;
      color: #2c5282;
      border-bottom: 1.5px solid #90cdf4;
      padding-bottom: 4px;
      margin: 28px 0 10px 0;
    }

    h3 {
      font-size: 13pt;
      font-weight: 700;
      color: #2d3748;
      margin: 20px 0 6px 0;
    }

    h4 {
      font-size: 11.5pt;
      font-weight: 700;
      color: #4a5568;
      margin: 14px 0 5px 0;
    }

    /* ── פסקאות ורשימות ── */
    p { margin: 6px 0 10px 0; }

    ul, ol {
      padding-right: 22px;
      padding-left: 0;
      margin: 6px 0 10px 0;
    }

    li { margin-bottom: 5px; }

    /* ── קוד inline ── */
    code {
      font-family: 'Courier New', Consolas, monospace;
      font-size: 9.5pt;
      color: #c53030;
      background: #fff5f5;
      padding: 1px 5px;
      border-radius: 3px;
      direction: ltr;
      unicode-bidi: embed;
    }

    /* ── בלוק קוד ── */
    pre {
      background: #2d3748;
      color: #e2e8f0;
      padding: 14px 16px;
      border-radius: 6px;
      font-family: 'Courier New', Consolas, monospace;
      font-size: 9pt;
      line-height: 1.5;
      direction: ltr;
      text-align: left;
      margin: 12px 0;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    pre code {
      background: transparent;
      color: inherit;
      padding: 0;
      border-radius: 0;
      font-size: inherit;
    }

    /* ── טבלאות ── */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 10pt;
    }

    th {
      background: #2d3748;
      color: #ffffff;
      padding: 8px 10px;
      text-align: right;
      font-weight: 700;
      border: 1px solid #4a5568;
    }

    td {
      padding: 7px 10px;
      border: 1px solid #cbd5e0;
      vertical-align: top;
    }

    tr:nth-child(even) td { background: #f7fafc; }

    /* ── קו מפריד ── */
    hr {
      border: none;
      border-top: 1px solid #e2e8f0;
      margin: 18px 0;
    }

    /* ── blockquote ── */
    blockquote {
      border-right: 4px solid #3182ce;
      border-left: none;
      margin: 10px 0;
      padding: 8px 14px 8px 0;
      background: #ebf8ff;
      color: #2b6cb0;
      border-radius: 0 4px 4px 0;
    }

    strong { font-weight: 700; }

    /* ── הגדרות כותרת עמוד ראשון ── */
    .cover {
      text-align: center;
      padding: 60px 0 40px 0;
      border-bottom: 3px solid #3182ce;
      margin-bottom: 30px;
    }
    .cover h1 { border: none; font-size: 26pt; }
    .cover .subtitle { font-size: 13pt; color: #718096; margin-top: 8px; }
  </style>
</head>
<body>
""" + html_body + """
</body>
</html>"""

# ── שמירת HTML לקובץ זמני ──
html_path = os.path.abspath("הסבר_מלא_temp.html")
with open(html_path, "w", encoding="utf-8") as f:
    f.write(full_html)

# ── הרצת Edge Headless להמרת HTML ל-PDF ──
output_path = os.path.abspath("הסבר_מלא.pdf")
edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

cmd = [
    edge_exe,
    "--headless",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-extensions",
    f"--print-to-pdf={output_path}",
    "--print-to-pdf-no-header",
    f"file:///{html_path.replace(chr(92), '/')}",
]

result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

# ── ניקוי קובץ HTML זמני ──
if os.path.exists(html_path):
    os.remove(html_path)

# ── בדיקת תוצאה ──
if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
    size_kb = os.path.getsize(output_path) // 1024
    print(f"PDF נוצר בהצלחה: הסבר_מלא.pdf ({size_kb} KB)")
else:
    print("שגיאה ביצירת PDF")
    print("stdout:", result.stdout)
    print("stderr:", result.stderr)
