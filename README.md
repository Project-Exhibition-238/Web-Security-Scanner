# Web-Security-Scanner

Comprehensive web application security scanner with both fast and ultra-comprehensive vulnerability detection modes.

---

## Features

- Scan for common web vulnerabilities including SQL Injection, XSS, Command Injection, Open Redirect, LDAP Injection, XML Injection, NoSQL Injection, Server-Side Template Injection, Path Traversal, and more
- Supports two scanner modes:
  - **Fast Mode**: Lower payload count for quicker scans
  - **Comprehensive Mode**: Extensive payloads and injection points for maximum thoroughness
- Smart HTTP/HTTPS fallback for reliable scanning
- Modular design with multiple analysis modules (Security Headers, TLS/SSL, Advanced Checks, Content Analysis, Port Scanning)

---

## Getting Started

### Installation

1. Clone the repository:
  git clone https://github.com/Project-Exhibition-238/Web-Security-Scanner.git
  cd Web-Security-Scanner

2. Create a virtual environment and install dependencies:
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt

3. Start Redis server (required for Celery task queue):
  sudo service redis-server start

### Running the scanner

1. Start the Celery worker:
  celery -A tasks.celery_app worker --loglevel=info

2. Run the Flask web application:
  python main.py

3. Open your browser and navigate to `http://localhost:5000` to use the scanner UI

## Switching Vulnerability Scanner Modes

Your project includes two vulnerability scanner files:

- `vulnerability_checks_fast.py` — Fast mode with fewer payloads
- `vulnerability_checks_comprehensive.py` — Comprehensive mode with full payloads

**To switch between modes:**

Move the `vulnerability_checks_fast.py` from Mode Change to the same directory as `main.py` for fast mode.
Leave the `vulnerability_checks_fast.py` in Mode Change for comprehensive mode.
