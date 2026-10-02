# sentinel-detect
Sentinel reads those logs automatically, spots attack patterns, and prints an alert saying who attacked, how, how serious it is, and which MITRE ATT&amp;CK technique it matches. MITRE ATT&amp;CK is the industry-standard catalog of attack methods


# 🛡️ Sentinel Detect

### Lightweight Log-Based Threat Detection Engine

Sentinel Detect is a Python-based defensive security tool that analyzes SSH authentication and web server logs to identify suspicious activity, correlate events, and generate actionable security alerts.

> **Attack → Understand → Detect → Defend**

Built for cybersecurity learning, security monitoring, SOC practice, and authorized defensive analysis.

---

 🚀 Features

- 🔐 SSH authentication log analysis
- 🌐 Nginx/Apache web access-log analysis
- 🚨 Brute-force detection
- 🎯 Password-spraying detection
- 🔓 Successful login after brute-force activity
- 👑 Direct root-login detection
- 🔎 Web scanner / reconnaissance detection
- 💉 SQL injection indicator detection
- 📂 Path-traversal and sensitive-file access detection
- 🧪 XSS indicator detection
- 💻 Command-injection / webshell probe detection
- 🧠 Stateful sliding-window detection
- 🗺️ MITRE ATT&CK technique mapping
- ⏱️ Alert cooldown support
- ✅ IP allowlisting
- 📋 Custom detection rules
- 📊 Terminal, JSON, and HTML reports
- 🔥 Firewall blocking suggestions
- 🧪 Built-in synthetic attack demonstrations
- ✅ Automated self-tests
- 📡 Follow mode for continuous log monitoring
- 📦 Zero required third-party dependencies

---

 Why Sentinel?

Traditional log analysis can require manually searching thousands of log entries.

Sentinel converts raw security logs into structured security events and evaluates those events against detection rules.

```text
Raw Logs
   │
   ▼
Log Parser
   │
   ▼
Security Events
   │
   ▼
Detection Engine
   │
   ├── Threshold Detection
   ├── Sliding Windows
   ├── Event Correlation
   ├── Allowlisting
   └── Cooldowns
   │
   ▼
Security Alerts
   │
   ├── Terminal
   ├── JSON
   └── HTML
   │
   ▼
Security Investigation

| Rule    | Detection                              | Severity | MITRE ATT&CK          |
| ------- | -------------------------------------- | -------- | --------------------- |
| SSH-001 | SSH Brute Force                        | High     | T1110.001             |
| SSH-002 | Password Spraying                      | High     | T1110.003             |
| SSH-003 | Login After Brute Force                | Critical | T1110 / T1078         |
| SSH-004 | Direct Root Login                      | Medium   | T1078.003             |
| WEB-001 | Web Scanner / 404 Flood                | Medium   | T1595.002 / T1595.003 |
| WEB-002 | SQL Injection Indicators               | High     | T1190                 |
| WEB-003 | Path Traversal / Sensitive File Access | High     | T1190 / T1083         |
| WEB-004 | Offensive Tool User-Agent              | Low      | T1595.002             |
| WEB-005 | XSS Indicators                         | Medium   | T1190                 |
| WEB-006 | Command Injection / Webshell Probe     | High     | T1190 / T1059         |
<img width="1920" height="1080" alt="Screenshot from 2026-10-02 12-59-58" src="https://github.com/user-attachments/assets/cfe71a50-4f0c-4917-af49-d98cd0e203b0" />


Requirements
Python 3.10+
Linux recommended for real system-log monitoring
No required external dependencies

Clone the repository:

git clone https://github.com/bibeksec/sentinel-detect.git
cd sentinel-detect

Run the built-in demonstration:

python3 sentinel.py --demo

Run the self-test suite:

python3 sentinel.py selftest

List available detection rules:

python3 sentinel.py rules
