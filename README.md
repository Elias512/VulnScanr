```markdown
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

# 🔍 VulnScanr - Web Vulnerability Scanner

A professional-grade web vulnerability scanner built in Python for detecting a wide range of security issues, including SQL Injection, XSS, Command Injection, and more. Designed as a Final Year Project for BSc Computer Science.

## 🚀 Features

- **10+ Vulnerability Scanners** covering OWASP Top 10:
  - SQL Injection (error-based, union-based, boolean blind)
  - Cross-Site Scripting (XSS) – reflected, DOM‑based
  - Command Injection
  - Local/Remote File Inclusion (LFI/RFI)
  - Path Traversal
  - Security Headers Check (missing headers)
  - CSRF (missing tokens)
  - Brute Force (weak password detection)
  - Open Redirect
  - Directory Listing Exposure
- **Dual Scan Modes**:
  - **Crawl & Scan** (recommended): automatically discovers pages/forms and tests them.
  - **Legacy Mode**: preconfigured for DVWA quick demos.
- **Web Crawler** – discovers URLs and forms up to configurable depth.
- **Professional Reporting** – generates HTML and JSON reports with severity breakdowns.
- **Interactive Dashboard** – a standalone HTML/JS dashboard (`dashboard.html`) that loads JSON reports and displays:
  - Summary cards (total, critical, high, medium, low)
  - Pie chart of vulnerability types
  - Filterable and sortable table of findings
  - Scan metadata (target, date)
- **Graphical User Interface** – Tkinter-based GUI with log viewer, results table, and one‑click report opening.
- **Modular Architecture** – easy to extend with new vulnerability checks.
- **Verbose Logging** – detailed output for debugging and learning.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/Elias512/VulnScanr.git
cd VulnScanr

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage

VulnScanr provides two scanning modes: **Crawl & Scan** (for any website) and **Legacy** (DVWA only). The GUI offers both options; from the command line you can use the following arguments.

### Recommended: Crawl & Scan (Works on any website)

```bash
# Full crawl + all vulnerability scans
python -m src http://example.com --crawl-and-scan

# With verbose output
python -m src http://example.com --crawl-and-scan -v
```

### Legacy Mode (DVWA only – individual scanners)

```bash
# Full legacy scan (all DVWA-specific tests)
python -m src http://localhost:8080 --full

# Individual scans (DVWA only)
python -m src http://localhost:8080 --sql
python -m src http://localhost:8080 --xss
python -m src http://localhost:8080 --ci
python -m src http://localhost:8080 --fi
python -m src http://localhost:8080 --pt
python -m src http://localhost:8080 --headers
python -m src http://localhost:8080 --csrf
python -m src http://localhost:8080 --bf
python -m src http://localhost:8080 --openredirect
python -m src http://localhost:8080 --dirlisting
```

### Launch the GUI

```bash
python -m src --gui
```

## 📊 Scan Modes Explained

| Mode | Command | Description |
|------|---------|-------------|
| **Crawl & Scan** | `--crawl-and-scan` | **Recommended for any website.** Crawls the target to discover all pages, forms, and parameters, then runs all vulnerability scanners on the discovered targets. |
| **Legacy** | `--sql`, `--xss`, … | **DVWA only.** Tests a hardcoded set of DVWA URLs. Useful for quick demonstrations or when testing a local DVWA instance. |

## 📈 Interactive Dashboard

After a scan, you can visualize the results using the standalone dashboard:

1. Open `dashboard.html` in any modern browser.
2. Click **"Load JSON Report"** and select a JSON file from the `reports/` folder.
3. Explore the summary, chart, and detailed table – filter and sort as needed.

The dashboard uses **Chart.js** and requires no server – it runs entirely in your browser.

## 🧪 Supported Vulnerabilities

- **SQL Injection** – Error-based, union-based, boolean blind
- **Cross-Site Scripting (XSS)** – Reflected, DOM‑based
- **Command Injection** – OS command execution
- **File Inclusion** – Local & Remote File Inclusion (LFI/RFI)
- **Path Traversal** – Directory traversal attacks
- **Security Headers** – Checks for missing HTTP security headers (HSTS, CSP, etc.)
- **CSRF** – Forms without anti‑CSRF tokens
- **Brute Force** – Weak passwords on login forms
- **Open Redirect** – Unvalidated redirects
- **Directory Listing** – Exposed directory indexes

## 📁 Project Structure

```
VulnScanr/
├── src/
│   ├── crawler/
│   │   └── crawler.py
│   ├── scanners/
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   ├── command_injection.py
│   │   ├── file_inclusion.py
│   │   ├── path_traversal.py
│   │   ├── headers.py
│   │   ├── csrf.py
│   │   ├── bruteforce.py
│   │   ├── open_redirect.py
│   │   └── directory_listing.py
│   ├── utils/
│   │   ├── logger.py
│   │   └── reporter.py
│   ├── gui/
│   │   └── main_window.py
│   ├── __main__.py
│   └── scanner.py
├── reports/                # Generated HTML/JSON reports
├── tests/
├── dashboard.html          # Standalone interactive dashboard
├── requirements.txt
├── README.md
└── LICENSE
```

## 🎓 Academic Project

This project was developed as a **Final Year Project for BSc Computer Science**, demonstrating practical cybersecurity skills, software engineering principles, and a deep understanding of web application vulnerabilities.

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**. Unauthorised scanning of systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse.

## 📄 License

MIT License – see the [LICENSE](LICENSE) file for details.
```
