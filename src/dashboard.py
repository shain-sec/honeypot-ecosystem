"""
Honeypot Dashboard — Component 5
Flask app serving the analyst dashboard with:
  - Live attack feed
  - Attacker profiles with risk scores
  - Charts: attacks over time, protocol split, profile distribution
  - Per-IP deep-dive
Runs on port 8080 (separate from the honeypot on 5000)
"""

from flask import Flask, jsonify, render_template_string
import sqlite3, json, os
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "honeypot.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot Ecosystem — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;--purple:#bc8cff;--text:#e6edf3;--muted:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
  header{background:var(--panel);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:700}header span{color:var(--muted);font-size:12px}
  .badge{background:#238636;color:#fff;font-size:11px;padding:2px 8px;border-radius:12px;margin-left:8px}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:20px 24px}
  .stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px}
  .stat .val{font-size:32px;font-weight:700;margin:6px 0}
  .stat .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
  .stat .delta{font-size:12px;margin-top:4px}
  .charts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;padding:0 24px 20px}
  .chart-box{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
  .chart-box h3{font-size:13px;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.5px}
  .main{display:grid;grid-template-columns:1fr 380px;gap:14px;padding:0 24px 24px}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:8px 12px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
  td{padding:9px 12px;border-bottom:1px solid #21262d;font-size:13px}
  tr:hover td{background:#1c2128}
  .profile-chip{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
  .APT{background:#3d1a1a;color:#f85149;border:1px solid #f8514940}
  .BruteForcer{background:#3d2a0a;color:#d29922;border:1px solid #d2992240}
  .WebExplorer{background:#0a2a3d;color:#58a6ff;border:1px solid #58a6ff40}
  .OpportunisticBot{background:#1a2a1a;color:#3fb950;border:1px solid #3fb95040}
  .risk-bar{height:6px;border-radius:3px;background:#21262d;position:relative}
  .risk-fill{height:100%;border-radius:3px;transition:width .4s}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
  .panel h3{font-size:14px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
  .feed-item{padding:8px 0;border-bottom:1px solid #21262d;display:flex;gap:10px;align-items:flex-start}
  .feed-item:last-child{border:none}
  .sev{width:6px;height:6px;border-radius:50%;margin-top:5px;flex-shrink:0}
  .CRITICAL{background:#f85149}.HIGH{background:#d29922}.MEDIUM{background:#58a6ff}.LOW{background:#3fb950}
  .feed-ts{color:var(--muted);font-size:11px;white-space:nowrap}
  .refresh-btn{margin-left:auto;background:#238636;border:none;color:#fff;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:13px}
  .refresh-btn:hover{background:#2ea043}
  canvas{max-height:180px}
</style>
</head>
<body>

<header>
  <div>🍯</div>
  <h1>Honeypot Ecosystem <span class="badge">LIVE</span></h1>
  <span id="clock"></span>
  <button class="refresh-btn" onclick="loadAll()">↻ Refresh</button>
</header>

<!-- KPI Cards -->
<div class="grid">
  <div class="stat"><div class="lbl">Total Attacks</div><div class="val" id="kpi-total" style="color:var(--red)">—</div><div class="delta" id="kpi-web" style="color:var(--muted)"></div></div>
  <div class="stat"><div class="lbl">Unique Attackers</div><div class="val" id="kpi-ips" style="color:var(--orange)">—</div><div class="delta" id="kpi-new" style="color:var(--green)"></div></div>
  <div class="stat"><div class="lbl">SSH Sessions</div><div class="val" id="kpi-ssh" style="color:var(--blue)">—</div><div class="delta" id="kpi-ssh-success" style="color:var(--muted)"></div></div>
  <div class="stat"><div class="lbl">Critical Threats</div><div class="val" id="kpi-critical" style="color:var(--purple)">—</div><div class="delta" id="kpi-apt" style="color:var(--muted)"></div></div>
</div>

<!-- Charts -->
<div class="charts">
  <div class="chart-box"><h3>Attack Volume (24h)</h3><canvas id="chartTimeline"></canvas></div>
  <div class="chart-box"><h3>Protocol Split</h3><canvas id="chartProtocol"></canvas></div>
  <div class="chart-box"><h3>Attacker Profiles</h3><canvas id="chartProfiles"></canvas></div>
</div>

<!-- Main content -->
<div class="main">
  <!-- Attacker table -->
  <div class="panel">
    <h3>🎯 Attacker Profiles — ML Classification</h3>
    <table>
      <thead><tr><th>IP Address</th><th>Profile</th><th>Risk Score</th><th>Attempts</th><th>Protocols</th><th>Confidence</th></tr></thead>
      <tbody id="profile-table"></tbody>
    </table>
  </div>

  <!-- Live feed -->
  <div class="panel">
    <h3>📡 Live Attack Feed</h3>
    <div id="live-feed"></div>
  </div>
</div>

<script>
let timelineChart, protocolChart, profileChart;

function initCharts(){
  const defaults = { color:'#8b949e', borderColor:'#30363d' };
  Chart.defaults.color = defaults.color;

  timelineChart = new Chart(document.getElementById('chartTimeline'),{
    type:'bar',
    data:{labels:[],datasets:[
      {label:'HTTP',data:[],backgroundColor:'#58a6ff88',borderRadius:3},
      {label:'SSH', data:[],backgroundColor:'#d2992288',borderRadius:3}
    ]},
    options:{plugins:{legend:{labels:{boxWidth:10,font:{size:11}}}},
             scales:{x:{grid:{color:'#21262d'},ticks:{font:{size:10}}},
                     y:{grid:{color:'#21262d'},beginAtZero:true}},
             responsive:true,maintainAspectRatio:true}
  });

  protocolChart = new Chart(document.getElementById('chartProtocol'),{
    type:'doughnut',
    data:{labels:['HTTP','SSH'],datasets:[{data:[0,0],
      backgroundColor:['#58a6ff','#d29922'],borderWidth:0,hoverOffset:4}]},
    options:{plugins:{legend:{position:'bottom',labels:{font:{size:11},boxWidth:10}}},
             responsive:true,cutout:'65%'}
  });

  profileChart = new Chart(document.getElementById('chartProfiles'),{
    type:'doughnut',
    data:{labels:['OpportunisticBot','BruteForcer','WebExplorer','APT'],
      datasets:[{data:[0,0,0,0],
        backgroundColor:['#3fb950','#d29922','#58a6ff','#f85149'],
        borderWidth:0,hoverOffset:4}]},
    options:{plugins:{legend:{position:'bottom',labels:{font:{size:11},boxWidth:10}}},
             responsive:true,cutout:'65%'}
  });
}

async function loadAll(){
  const [stats, profiles, feed, timeline] = await Promise.all([
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/profiles').then(r=>r.json()),
    fetch('/api/feed').then(r=>r.json()),
    fetch('/api/timeline').then(r=>r.json()),
  ]);
  updateKPIs(stats);
  updateProfiles(profiles, stats);
  updateFeed(feed);
  updateCharts(stats, profiles, timeline);
}

function updateKPIs(s){
  document.getElementById('kpi-total').textContent    = (s.total_web + s.total_ssh).toLocaleString();
  document.getElementById('kpi-web').textContent      = `HTTP: ${s.total_web} | SSH: ${s.total_ssh}`;
  document.getElementById('kpi-ips').textContent      = s.unique_ips;
  document.getElementById('kpi-new').textContent      = `${s.profiled} profiled by ML`;
  document.getElementById('kpi-ssh').textContent      = s.total_ssh.toLocaleString();
  document.getElementById('kpi-ssh-success').textContent = `${s.ssh_success} successful logins`;
  document.getElementById('kpi-critical').textContent = s.critical_events;
  document.getElementById('kpi-apt').textContent      = `${s.apt_count} APT | ${s.brute_count} BruteForce`;
}

function riskColor(r){ return r>0.8?'#f85149':r>0.6?'#d29922':r>0.3?'#58a6ff':'#3fb950'; }

function updateProfiles(profiles){
  const tb = document.getElementById('profile-table');
  tb.innerHTML = profiles.map(p=>`
    <tr>
      <td style="font-family:monospace;color:#cdd9e5">${p.source_ip}</td>
      <td><span class="profile-chip ${p.profile_label}">${p.profile_label}</span></td>
      <td>
        <div class="risk-bar"><div class="risk-fill" style="width:${p.risk_score*100}%;background:${riskColor(p.risk_score)}"></div></div>
        <span style="font-size:11px;color:var(--muted)">${(p.risk_score*100).toFixed(0)}%</span>
      </td>
      <td>${p.total_attempts}</td>
      <td><span style="color:var(--muted)">${p.protocols_used||'—'}</span></td>
      <td style="color:var(--muted)">${(p.confidence*100).toFixed(0)}%</td>
    </tr>`).join('');
}

function sevIcon(s){ const m={CRITICAL:'🔴',HIGH:'🟠',MEDIUM:'🟡',LOW:'🟢'}; return m[s]||'⚪'; }

function updateFeed(feed){
  const el = document.getElementById('live-feed');
  el.innerHTML = feed.map(f=>`
    <div class="feed-item">
      <div class="sev ${f.severity}"></div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;justify-content:space-between">
          <span style="font-family:monospace;color:#cdd9e5;font-size:12px">${f.source_ip}</span>
          <span class="feed-ts">${f.timestamp.slice(11,19)}</span>
        </div>
        <div style="color:var(--muted);font-size:12px;margin-top:2px">
          <span style="color:${f.protocol==='SSH'?'#d29922':'#58a6ff'}">${f.protocol}</span>
          · ${f.event_type} ${f.username?'<b>'+f.username+'</b>':''}
          ${f.payload?'<span style="color:#8b949e;font-size:11px">'+f.payload.slice(0,30)+'</span>':''}
        </div>
      </div>
    </div>`).join('');
}

function updateCharts(stats, profiles, timeline){
  // Protocol doughnut
  protocolChart.data.datasets[0].data = [stats.total_web, stats.total_ssh];
  protocolChart.update();

  // Profile doughnut
  const pCount = {OpportunisticBot:0, BruteForcer:0, WebExplorer:0, APT:0};
  profiles.forEach(p=>{ if(pCount[p.profile_label]!==undefined) pCount[p.profile_label]++; });
  profileChart.data.datasets[0].data = Object.values(pCount);
  profileChart.update();

  // Timeline
  if(timeline && timeline.labels){
    timelineChart.data.labels = timeline.labels;
    timelineChart.data.datasets[0].data = timeline.http;
    timelineChart.data.datasets[1].data = timeline.ssh;
    timelineChart.update();
  }
}

function updateClock(){
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}

initCharts();
loadAll();
setInterval(loadAll, 15000);
setInterval(updateClock, 1000);
</script>
</body></html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/stats")
def api_stats():
    conn = get_conn()
    stats = {
        "total_web":      conn.execute("SELECT COUNT(*) FROM web_events").fetchone()[0],
        "total_ssh":      conn.execute("SELECT COUNT(*) FROM ssh_events").fetchone()[0],
        "unique_ips":     conn.execute("SELECT COUNT(DISTINCT source_ip) FROM unified_log").fetchone()[0],
        "ssh_success":    conn.execute("SELECT SUM(success) FROM ssh_events").fetchone()[0] or 0,
        "critical_events":conn.execute("SELECT COUNT(*) FROM unified_log WHERE severity='CRITICAL'").fetchone()[0],
        "profiled":       conn.execute("SELECT COUNT(*) FROM attacker_profiles").fetchone()[0],
        "apt_count":      conn.execute("SELECT COUNT(*) FROM attacker_profiles WHERE profile_label='APT'").fetchone()[0],
        "brute_count":    conn.execute("SELECT COUNT(*) FROM attacker_profiles WHERE profile_label='BruteForcer'").fetchone()[0],
    }
    conn.close()
    return jsonify(stats)

@app.route("/api/profiles")
def api_profiles():
    conn = get_conn()
    rows = conn.execute("""
        SELECT source_ip, profile_label, confidence, total_attempts,
               unique_creds, protocols_used, risk_score
        FROM attacker_profiles ORDER BY risk_score DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/feed")
def api_feed():
    conn = get_conn()
    rows = conn.execute("""
        SELECT timestamp, source_ip, protocol, event_type, username, payload, severity
        FROM unified_log ORDER BY timestamp DESC LIMIT 40
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/timeline")
def api_timeline():
    conn = get_conn()
    # Last 12 hours grouped by hour
    http_rows = conn.execute("""
        SELECT strftime('%H:00', timestamp) as hr, COUNT(*) as cnt
        FROM web_events
        WHERE timestamp >= datetime('now', '-12 hours')
        GROUP BY hr ORDER BY hr
    """).fetchall()
    ssh_rows = conn.execute("""
        SELECT strftime('%H:00', timestamp) as hr, COUNT(*) as cnt
        FROM ssh_events
        WHERE timestamp >= datetime('now', '-12 hours')
        GROUP BY hr ORDER BY hr
    """).fetchall()
    conn.close()

    all_hours = sorted(set([r[0] for r in http_rows] + [r[0] for r in ssh_rows]))
    http_map = {r[0]: r[1] for r in http_rows}
    ssh_map  = {r[0]: r[1] for r in ssh_rows}

    return jsonify({
        "labels": all_hours or ["00:00","06:00","12:00","18:00"],
        "http":   [http_map.get(h, 0) for h in all_hours] or [0,0,0,0],
        "ssh":    [ssh_map.get(h, 0) for h in all_hours] or [0,0,0,0],
    })

@app.route("/api/report")
def api_report():
    conn = get_conn()
    profiles = conn.execute("""
        SELECT * FROM attacker_profiles ORDER BY risk_score DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(p) for p in profiles])

if __name__ == "__main__":
    print("[DASHBOARD] Starting on http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
