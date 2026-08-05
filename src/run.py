#!/usr/bin/env python3
"""
Honeypot Ecosystem — Master Setup & Runner
Run this single script to:
  1. Check and install all dependencies
  2. Initialise the SQLite database
  3. Simulate realistic attack traffic (Cowrie + Flask logs)
  4. Train the Random Forest ML profiler
  5. Generate the threat intelligence report
  6. Start the analysis dashboard
"""

import subprocess, sys, os

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

REQUIRED_PACKAGES = [
    "flask", "scikit-learn", "pandas", "numpy"
]

def step(n, title):
    print(f"\n{'='*65}")
    print(f"  STEP {n}: {title}")
    print(f"{'='*65}")

def install_deps():
    step(1, "Installing Python Dependencies")
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg.replace("-","_"))
            print(f"  ✓ {pkg} already installed")
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"  Installing: {', '.join(missing)}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", "-q", *missing
        ])
        print(f"  ✓ All packages installed")

def init_database():
    step(2, "Initialising SQLite Database")
    from database import init_db
    init_db()
    print("  ✓ All tables created (web_events, ssh_events, unified_log, attacker_profiles)")

def simulate_attacks():
    step(3, "Simulating Attack Traffic (Flask + Cowrie)")
    from cowrie_bridge.cowrie_bridge import simulate_attacks as run_sim
    run_sim(days_back=3)
    print("  ✓ Attack simulation complete")

def run_ml():
    step(4, "Training Random Forest & Profiling Attackers")
    from ml_profiler.profiler import train_and_classify, generate_report
    rf, le, df = train_and_classify()
    if rf:
        generate_report()
    print("  ✓ ML profiling complete")

def show_summary():
    step(5, "Database Summary")
    import sqlite3
    db = os.path.join(ROOT, "data", "honeypot.db")
    conn = sqlite3.connect(db)
    tables = ["web_events", "ssh_events", "unified_log", "attacker_profiles"]
    for t in tables:
        cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t:<25} {cnt:>6} rows")
    conn.close()

def start_dashboard():
    step(6, "Starting Dashboard")
    print("  Dashboard will be available at: http://localhost:8080")
    print("  Press Ctrl+C to stop\n")
    os.chdir(ROOT)
    os.system(f"{sys.executable} dashboard/dashboard.py")

if __name__ == "__main__":
    print("\n🍯 HONEYPOT ECOSYSTEM WITH ML-BASED ATTACKER PROFILING")
    print("   MSc Internship Project — Muhammed Shain (24MSCB004)")
    print("   Yenepoya (Deemed to be University)\n")

    install_deps()
    init_database()
    simulate_attacks()
    run_ml()
    show_summary()
    start_dashboard()
