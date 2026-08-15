# 🛡️ Honeypot Ecosystem with ML-Based Attacker Profiling

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)
![Cowrie](https://img.shields.io/badge/Cowrie-SSH%20Honeypot-orange)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Random%20Forest-green)
![SQLite](https://img.shields.io/badge/SQLite-Database-blue)
![License](https://img.shields.io/badge/License-MIT-success)

</p>

A multi-service honeypot ecosystem designed to capture real-world attack activity, classify attacker behaviour using Machine Learning, and provide centralized monitoring through an interactive dashboard.

Built to simulate real SOC workflows by combining offensive security techniques with defensive monitoring and analytics.

---

# 📌 Overview

Traditional security systems often block malicious activity before defenders can study attacker behaviour.

This project takes a different approach.

It intentionally exposes controlled services to attract attackers, capture their techniques, analyse collected telemetry, and classify attacker behaviour using Machine Learning.

The platform combines:

- Flask Web Honeypot
- Cowrie SSH Honeypot
- Random Forest ML Classifier
- SQLite Databases
- Centralized Dashboard
- Real-time Attack Analytics

---

# ✨ Key Features

- 🛡️ Multi-service honeypot deployment
- 🔐 SSH attack monitoring using Cowrie
- 🌐 Web application attack logging
- 🤖 ML-based attacker profiling
- 📊 Interactive security dashboard
- 🗄️ Centralized SQLite database
- 🐍 Python-based implementation

---

# 🏗️ Architecture

> *(Insert your architecture diagram here)*

```text
Attacker
    │
    ▼
Flask Honeypot ──────┐
                     │
Cowrie SSH Honeypot ─┤
                     ▼
              SQLite Database
                     ▼
          Machine Learning Engine
                     ▼
           Security Dashboard
```

---

# 🛠️ Technology Stack

| Category | Technologies |
|----------|--------------|
| Programming | Python |
| Web Framework | Flask |
| Honeypot | Cowrie |
| Database | SQLite |
| Machine Learning | Random Forest (Scikit-learn) |
| Operating Systems | Ubuntu, Kali Linux |
| Security Tools | Nmap, Hydra, SQLMap |
| Visualization | HTML, CSS, Bootstrap |

---

# 🔄 Project Workflow

```text
Reconnaissance

↓

Attack Simulation

↓

Honeypot Logging

↓

Data Collection

↓

Machine Learning Classification

↓

Dashboard Visualisation

↓

Security Analysis
```

---

# 📊 Results

During testing the project successfully demonstrated:

- 500+ SSH brute-force attempts captured
- 200+ SQL injection payloads recorded
- 87% Machine Learning classification accuracy
- Four attacker behaviour profiles identified

---

# 📷 Screenshots

### Dashboard

*assets/Honeypot_Dashborad.png*

---

### Live Attack Logs

*assets/live_attack.png*

---

### ML Attacker Profiling

*assets/ML_Profiling.png*

---

### Login Portal

*assets/Logins_Page.png*

---

# 🚀 Getting Started

Clone the repository

```bash
git clone https://github.com/shain-sec/honeypot-ecosystem.git
cd honeypot-ecosystem
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python run.py
```

---

# 📁 Project Structure

```text
src/
assets/
docs/
diagrams/
data/
```

---

# 📚 Documentation

Detailed documentation is available in the `docs/` directory, including:

- Project Report
- Presentation
- Architecture
- Installation Guide

---

# 🎯 Future Improvements

- Elasticsearch integration
- Docker deployment
- Threat intelligence feeds
- Email alerting
- MITRE ATT&CK mapping
- Multi-node deployment

---

# 👨‍💻 Author

**Muhammed Shain**

- M.Sc. Cybersecurity
- Certified Ethical Hacker (CEH)
- Security Operations | Threat Detection | Penetration Testing

If you find this project useful, consider giving it a ⭐.
