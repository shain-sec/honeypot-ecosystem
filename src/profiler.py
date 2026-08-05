"""
ML Attacker Profiling Engine — Component 4
Random Forest Classifier that categorises attackers into 4 profiles:

  OpportunisticBot  — automated scanners hitting many IPs randomly
  BruteForcer       — persistent credential guessing from one IP
  WebExplorer       — targeted web app exploit attempts
  APT               — advanced persistent threat, slow and stealthy

Feature Extraction from unified SQLite → Pandas DataFrame → Normalize → RF Classify
"""

import sqlite3, json, os, sys
import numpy as np
import pandas as pd
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "honeypot.db")


# ─── 1. Feature Extraction ──────────────────────────────────────────────────
def extract_features() -> pd.DataFrame:
    """
    Pull all events from DB and engineer per-IP behavioural features.
    These features are what the RF classifier uses.
    """
    conn = sqlite3.connect(DB_PATH)

    # Web honeypot features
    web = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(*) as http_attempts,
               COUNT(DISTINCT username) as unique_web_usernames,
               COUNT(DISTINCT password) as unique_web_passwords,
               SUM(CASE WHEN attack_pattern='SQLi'      THEN 1 ELSE 0 END) as sqli_count,
               SUM(CASE WHEN attack_pattern='XSS'       THEN 1 ELSE 0 END) as xss_count,
               SUM(CASE WHEN attack_pattern='PathEnum'  THEN 1 ELSE 0 END) as path_enum_count,
               SUM(CASE WHEN attack_pattern='BruteForce'THEN 1 ELSE 0 END) as brute_web_count,
               SUM(CASE WHEN attack_pattern='Scan'      THEN 1 ELSE 0 END) as scan_count,
               COUNT(DISTINCT DATE(timestamp)) as active_days_web
        FROM web_events
        GROUP BY source_ip
    """, conn)

    # SSH honeypot features
    ssh = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(*) as ssh_attempts,
               COUNT(DISTINCT username) as unique_ssh_usernames,
               COUNT(DISTINCT password) as unique_ssh_passwords,
               AVG(session_duration) as avg_session_duration,
               MAX(session_duration) as max_session_duration,
               SUM(success) as successful_logins,
               COUNT(DISTINCT DATE(timestamp)) as active_days_ssh
        FROM ssh_events
        GROUP BY source_ip
    """, conn)

    # Command execution features
    cmd = pd.read_sql_query("""
        SELECT source_ip,
               COUNT(*) as cmd_events,
               SUM(CASE WHEN payload LIKE '%wget%' OR payload LIKE '%curl%' THEN 1 ELSE 0 END) as download_cmds,
               SUM(CASE WHEN payload LIKE '%cat /etc%' OR payload LIKE '%shadow%' THEN 1 ELSE 0 END) as recon_cmds,
               SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_events
        FROM unified_log
        WHERE event_type='command_exec'
        GROUP BY source_ip
    """, conn)

    conn.close()

    # Merge all feature sets
    df = pd.merge(web, ssh, on="source_ip", how="outer").fillna(0)
    df = pd.merge(df, cmd, on="source_ip", how="outer").fillna(0)

    # Engineered features
    df["total_attempts"]   = df["http_attempts"] + df["ssh_attempts"]
    df["unique_creds"]     = df[["unique_web_usernames","unique_web_passwords",
                                  "unique_ssh_usernames","unique_ssh_passwords"]].max(axis=1)
    df["multi_protocol"]   = ((df["http_attempts"] > 0) & (df["ssh_attempts"] > 0)).astype(int)
    df["injection_ratio"]  = (df["sqli_count"] + df["xss_count"]) / (df["http_attempts"].clip(lower=1))
    df["ssh_persistence"]  = df["avg_session_duration"].fillna(0)
    df["active_days"]      = df[["active_days_web","active_days_ssh"]].max(axis=1)

    return df


# ─── 2. Rule-Based Labelling (for synthetic training data) ──────────────────
def label_attacker(row) -> str:
    """
    Heuristic labeller — determines the ground-truth profile for training.
    In production, analyst-verified labels are used.
    """
    ip = str(row["source_ip"])

    # Known profile IPs from simulation
    APT_IPS   = {"198.54.117.197","5.188.206.60"}
    WEB_IPS   = {"176.65.148.10","77.247.110.30"}
    BRUTE_IPS = {"103.99.0.122","45.142.212.100","194.165.16.4"}
    BOT_IPS   = {"185.220.101.42","195.54.160.149","91.92.251.103"}

    if ip in APT_IPS:   return "APT"
    if ip in WEB_IPS:   return "WebExplorer"
    if ip in BRUTE_IPS: return "BruteForcer"
    if ip in BOT_IPS:   return "OpportunisticBot"

    # Feature-based fallback for unseen IPs
    if row["successful_logins"] > 0 and row["cmd_events"] > 5:   return "APT"
    if row["injection_ratio"] > 0.4:                               return "WebExplorer"
    if row["unique_creds"] > 10 and row["avg_session_duration"] < 5: return "BruteForcer"
    return "OpportunisticBot"


# ─── 3. Train Random Forest ─────────────────────────────────────────────────
FEATURES = [
    "http_attempts","ssh_attempts","unique_creds","sqli_count","xss_count",
    "path_enum_count","brute_web_count","scan_count","avg_session_duration",
    "successful_logins","cmd_events","download_cmds","recon_cmds",
    "critical_events","multi_protocol","injection_ratio","active_days"
]

def train_and_classify():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

    print("\n[ML ENGINE] Extracting features from database...")
    df = extract_features()

    if df.empty or len(df) < 4:
        print("[ML ENGINE] Not enough data. Run the attack simulator first.")
        return None, None, None

    # Label all IPs
    df["label"] = df.apply(label_attacker, axis=1)

    X = df[FEATURES].fillna(0)
    y = df["label"]

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    print(f"[ML ENGINE] Training on {len(df)} IP profiles")
    print(f"[ML ENGINE] Label distribution:\n{y.value_counts().to_string()}\n")

    # Train/test split — need at least 2x num_classes samples to stratify
    n_classes = len(np.unique(y_enc))
    if len(df) >= n_classes * 4:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=0.25, random_state=42, stratify=y_enc)
    else:
        X_train, X_test, y_train, y_test = X, X, y_enc, y_enc

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=42,
        class_weight="balanced"
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[ML ENGINE] Accuracy: {acc*100:.1f}%")
    print("\n[ML ENGINE] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_,
                                 zero_division=0))

    # Feature importance
    importances = pd.Series(rf.feature_importances_, index=FEATURES)
    print("[ML ENGINE] Top 5 Features:")
    print(importances.sort_values(ascending=False).head(5).to_string())

    # ─ Classify all IPs and write profiles to DB ─
    probs    = rf.predict_proba(X)
    preds    = rf.predict(X)
    labels   = le.inverse_transform(preds)
    confs    = probs.max(axis=1)

    conn = sqlite3.connect(DB_PATH)
    for i, row in df.iterrows():
        profile  = labels[i]
        conf     = float(confs[i])
        ip       = row["source_ip"]
        risk_map = {"APT": 0.95, "WebExplorer": 0.75, "BruteForcer": 0.55, "OpportunisticBot": 0.25}
        risk     = risk_map.get(profile, 0.3) * conf

        protocols = []
        if row["http_attempts"] > 0: protocols.append("HTTP")
        if row["ssh_attempts"]  > 0: protocols.append("SSH")

        conn.execute("""
            INSERT OR REPLACE INTO attacker_profiles
              (source_ip, profile_label, confidence, total_attempts, unique_creds,
               protocols_used, risk_score, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,datetime('now','-3 days'),datetime('now'))
        """, (ip, profile, conf, int(row["total_attempts"]),
              int(row["unique_creds"]), "/".join(protocols) or "HTTP", risk))

        # Back-fill attacker_profile in unified_log
        conn.execute("""
            UPDATE unified_log SET attacker_profile=? WHERE source_ip=?
        """, (profile, ip))

    conn.commit()
    conn.close()

    print(f"\n[ML ENGINE] Profiles written to database for {len(df)} IPs")
    return rf, le, df


# ─── 4. Report ──────────────────────────────────────────────────────────────
def generate_report():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    profiles = conn.execute("""
        SELECT * FROM attacker_profiles ORDER BY risk_score DESC
    """).fetchall()
    conn.close()

    if not profiles:
        print("[REPORT] No profiles found. Run train_and_classify() first.")
        return

    print("\n" + "="*65)
    print("  HONEYPOT ECOSYSTEM — ATTACKER THREAT INTELLIGENCE REPORT")
    print("="*65)
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total unique attackers profiled: {len(profiles)}")
    print("="*65)

    for p in profiles:
        risk = p["risk_score"]
        severity = "🔴 CRITICAL" if risk>0.8 else "🟠 HIGH" if risk>0.6 else "🟡 MEDIUM" if risk>0.3 else "🟢 LOW"
        print(f"\n  IP: {p['source_ip']:<22} Profile: {p['profile_label']:<18} {severity}")
        print(f"      Confidence: {p['confidence']*100:.0f}%  |  Risk Score: {p['risk_score']:.2f}")
        print(f"      Attempts: {p['total_attempts']}  |  Protocols: {p['protocols_used']}")

    print("\n" + "="*65)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    rf, le, df = train_and_classify()
    if rf is not None:
        generate_report()
