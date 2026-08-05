"""
Flask Web Honeypot — Component 1
Simulates a vulnerable web application with:
  - /login     → captures credential brute-force & stuffing
  - /admin     → lures attackers with a fake admin panel
  - /api/*     → captures API endpoint probing
  - /*         → catch-all for path enumeration & scanning
Logs: Source IP, Timestamp, HTTP Method, Request Path,
      User-Agent, POST Body, Attack Pattern
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3, json, re, os, hashlib
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "honeypot.db")

# ── Attack Pattern Classifier ──────────────────────────────────────────────
SQLI_PATTERNS  = [r"'", r"--", r"\bOR\b", r"\bUNION\b", r"1=1", r"DROP\b", r"SELECT\b"]
XSS_PATTERNS   = [r"<script", r"javascript:", r"onerror=", r"alert\(", r"<img"]
PATH_PATTERNS  = [r"\.\./", r"etc/passwd", r"\.env", r"\.git", r"wp-admin",
                  r"phpmyadmin", r"\.php", r"backup"]

def classify_attack(path, body, ua):
    text = f"{path} {body} {ua}".lower()
    for p in SQLI_PATTERNS:
        if re.search(p, text, re.IGNORECASE): return "SQLi"
    for p in XSS_PATTERNS:
        if re.search(p, text, re.IGNORECASE): return "XSS"
    for p in PATH_PATTERNS:
        if re.search(p, text, re.IGNORECASE): return "PathEnum"
    if path in ["/login", "/admin/login"] and request.method == "POST":
        return "BruteForce"
    if any(s in ua.lower() for s in ["nmap","nikto","masscan","zgrab","sqlmap","hydra"]):
        return "Scan"
    return "Probe"

def log_event(ip, method, path, ua, body, username, password, pattern):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO web_events
              (source_ip, http_method, request_path, user_agent, post_body,
               username, password, attack_pattern, session_id)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (ip, method, path, ua, body, username, password, pattern,
              hashlib.md5(f"{ip}{datetime.now().date()}".encode()).hexdigest()[:8]))
        # Also write to unified log
        conn.execute("""
            INSERT INTO unified_log
              (source_ip, protocol, event_type, username, payload, severity)
            VALUES (?,?,?,?,?,?)
        """, (ip, "HTTP", pattern, username, body,
              "HIGH" if pattern in ("SQLi","XSS") else
              "MEDIUM" if pattern in ("BruteForce","PathEnum") else "LOW"))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WEB LOG ERROR] {e}")

# ── HTML Templates (fake vulnerable-looking pages) ─────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>MyApp — Login</title>
<style>
  body{font-family:Arial;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.2);width:340px}
  h2{color:#333;margin-bottom:24px}
  input{width:100%;padding:10px;margin-bottom:16px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#0066cc;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}
  .error{color:red;font-size:13px;margin-bottom:10px}
  .footer{font-size:11px;color:#999;margin-top:16px;text-align:center}
</style></head>
<body><div class="box">
  <h2>🔐 Login</h2>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">MyApp v2.3 | Forgot password? <a href="/reset">Reset</a></div>
</div></body></html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin Panel</title>
<style>
  body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}
  h1{color:#ff6b6b}
  .cred{background:#16213e;padding:20px;border-left:4px solid #ff6b6b;margin:16px 0}
  input,button{padding:8px 12px;margin:4px}
  button{background:#ff6b6b;border:none;color:white;cursor:pointer;border-radius:4px}
</style></head>
<body>
  <h1>⚙️ Admin Panel — Restricted Access</h1>
  <div class="cred">
    <b>Database Credentials (DO NOT SHARE)</b><br>
    DB_HOST: db.internal.myapp.com<br>
    DB_USER: admin<br>
    DB_PASS: [REDACTED]
  </div>
  <form method="POST" action="/admin/login">
    <input name="username" placeholder="Admin username">
    <input name="password" type="password" placeholder="Admin password">
    <button>Login</button>
  </form>
</body></html>"""

# ── Routes ─────────────────────────────────────────────────────────────────
@app.before_request
def capture_all():
    """Log every single request — even static probes."""
    ip     = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua     = request.headers.get("User-Agent", "unknown")
    method = request.method
    path   = request.path
    body   = request.get_data(as_text=True)[:500]  # cap at 500 chars
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    pattern  = classify_attack(path, body, ua)
    log_event(ip, method, path, ua, body, username, password, pattern)

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        # Always fail — this is a honeypot!
        error = "Invalid username or password."
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/admin")
@app.route("/admin/login", methods=["GET","POST"])
def admin():
    return render_template_string(ADMIN_HTML)

@app.route("/api/users")
@app.route("/api/data")
@app.route("/api/config")
def fake_api():
    # Return plausible-looking fake data to keep attacker engaged
    return jsonify({"error": "Unauthorized", "code": 401,
                    "hint": "Try /api/v1/auth first"})

@app.route("/.env")
@app.route("/.git/config")
@app.route("/wp-admin")
@app.route("/phpmyadmin")
def honeytrap_files():
    return "Not Found", 404

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return render_template_string(LOGIN_HTML, error=None), 200

@app.route("/_honeypot/stats")
def stats():
    """Internal endpoint to view captured data."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        events = conn.execute(
            "SELECT * FROM web_events ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        conn.close()
        return jsonify([dict(e) for e in events])
    except:
        return jsonify([])

if __name__ == "__main__":
    print("[WEB HONEYPOT] Starting on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
