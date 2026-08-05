"""
Central SQLite Database — Honeypot Ecosystem
Aggregates events from Flask Web Honeypot + Cowrie SSH Honeypot
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "honeypot.db")

SCHEMA = """
-- ─── WEB HONEYPOT EVENTS (Flask) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS web_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip       TEXT NOT NULL,
    http_method     TEXT,
    request_path    TEXT,
    user_agent      TEXT,
    post_body       TEXT,
    username        TEXT,
    password        TEXT,
    attack_pattern  TEXT,   -- BruteForce | SQLi | XSS | PathEnum | Scan
    response_code   INTEGER DEFAULT 200,
    session_id      TEXT
);

-- ─── SSH HONEYPOT EVENTS (Cowrie) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip       TEXT NOT NULL,
    username        TEXT,
    password        TEXT,
    commands        TEXT,   -- JSON array of executed commands
    session_duration REAL,  -- seconds
    files_uploaded  TEXT,   -- JSON array
    success         INTEGER DEFAULT 0,  -- 1 if attacker "logged in"
    session_id      TEXT
);

-- ─── UNIFIED EVENT LOG (Normalised across both honeypots) ───────────────────
CREATE TABLE IF NOT EXISTS unified_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip       TEXT NOT NULL,
    protocol        TEXT NOT NULL,  -- HTTP | SSH
    event_type      TEXT,           -- login_attempt | command_exec | scan | inject
    username        TEXT,
    payload         TEXT,
    severity        TEXT DEFAULT 'LOW',  -- LOW | MEDIUM | HIGH | CRITICAL
    raw_event_id    INTEGER,
    attacker_profile TEXT            -- set by ML engine
);

-- ─── ML PROFILER RESULTS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT NOT NULL UNIQUE,
    profile_label   TEXT,    -- OpportunisticBot | BruteForcer | WebExplorer | APT
    confidence      REAL,
    total_attempts  INTEGER DEFAULT 0,
    unique_creds    INTEGER DEFAULT 0,
    payload_types   TEXT,    -- JSON
    protocols_used  TEXT,    -- HTTP | SSH | BOTH
    first_seen      DATETIME,
    last_seen       DATETIME,
    risk_score      REAL DEFAULT 0.0
);
"""

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[DB] Database initialised at {DB_PATH}")
    return DB_PATH

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

if __name__ == "__main__":
    init_db()
