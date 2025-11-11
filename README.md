![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)


\# 🔍 VulnScanr - Web Vulnerability Scanner



A professional web vulnerability scanner built in Python for detecting SQL Injection and Cross-Site Scripting (XSS) vulnerabilities.



\## 🚀 Features



\- \*\*SQL Injection Detection\*\* - Multiple attack vectors and detection methods

\- \*\*XSS Detection\*\* - Various payload types and context detection  

\- \*\*Automated Scanning\*\* - Automatic login and session management

\- \*\*Professional Reporting\*\* - HTML and JSON report generation

\- \*\*Modular Architecture\*\* - Easy to extend with new vulnerability scanners



\## 🛠️ Installation



```bash

\# Clone the repository

git clone https://github.com/yourusername/VulnScanr.git

cd VulnScanr



\# Create virtual environment

python -m venv venv



\# Activate virtual environment

\# Windows:

venv\\Scripts\\activate

\# Linux/Mac:

source venv/bin/activate



\# Install dependencies

pip install -r requirements.txt


\# Usage

# Full security scan
python -m src http://localhost:8080 --full

# SQL injection scan only
python -m src http://localhost:8080 --sql

# XSS scan only  
python -m src http://localhost:8080 --xss

# Verbose output
python -m src http://localhost:8080 --full -v






\# 🎯 Supported Vulnerabilities
# SQL Injection
Error-based detection
Union-based attacks
Boolean-based blind SQLi
Time-based detection

# Cross-Site Scripting (XSS)
Reflected XSS
DOM-based XSS
Various payload contexts
Event handler injection

\# 🏗️ Project Structure
VulnScanr/
├── src/
│   ├── scanners/
│   │   ├── sql_injection.py
│   │   └── xss.py
│   ├── utils/
│   │   ├── logger.py
│   │   └── reporter.py
│   └── scanner.py
├── tests/
├── docs/
├── requirements.txt
└── README.md

\# 🎓 Academic Project
This project was developed as a Final Year Project for BSc Computer Science, demonstrating practical cybersecurity skills and software engineering principles.

\# ⚠️ Disclaimer
This tool is intended for educational purposes and authorized penetration testing only. Always ensure you have proper authorization before scanning any systems.

\# 📄 License
MIT License - see LICENSE file for details
