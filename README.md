# WebAppFirewall (Python + Flask)

A lightweight Web Application Firewall (WAF) built in Python.  
It runs as a middleware layer in Flask and blocks suspicious requests before they reach app routes.

## Features

- Regex-based detection for:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Command Injection
  - Server-Side Template Injection (SSTI)
  - NoSQL Injection (NoSQLi)
  - XML External Entity (XXE)
  - Local/File Inclusion payload patterns
- `@app.before_request` inspection layer
- Automatic blocking with `403 Forbidden`
- SQLite logging of blocked attacks:
  - timestamp, IP, attack type, method, path, payload
- Request monitoring for all incoming traffic:
  - allowed/blocked status, path, method, detected type
- Admin authentication with hashed passwords
- Admin dashboard for attack summaries and recent logs
- Detection rule controls (enable/disable modules from admin dashboard)
- Per-rule sensitivity levels (`Low`, `Medium`, `High`) for relaxed/strict matching
- Admin rule testing panel to verify which rule/pattern matches a payload
- CSV export for request monitoring logs and blocked attack logs
- Simulation mode for college demo testing

## Tech Stack

- Backend: Python, Flask
- Detection: `re` (Regex), `urllib.parse`
- Database: SQLite
- UI: HTML + Tailwind CSS

## Project Structure

- `app.py` - main Flask app, WAF engine, DB setup, admin routes
- `templates/` - UI pages (home, simulation, blocked, admin login/dashboard)
- `requirements.txt` - Python dependencies
- `waf.db` - auto-created SQLite database on first run

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

App runs on: `http://127.0.0.1:5000`

## Default Admin Login

First run now uses an admin setup page:

- Open `http://127.0.0.1:5000/admin/setup`
- Create your initial admin username and password
- Then sign in at `http://127.0.0.1:5000/admin/login`

You can override with environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `APP_SECRET`

## Demo Payloads

Try these in Simulation Mode:

- `<script>alert(1)</script>` (XSS)
- `' OR '1'='1` (SQLi)
- `UNION SELECT password FROM users` (SQLi)
- `../../etc/passwd` (Path Traversal)
- `name=test; whoami` (Command Injection)
- `{{7*7}}` (SSTI)
- `{"username":{"$ne":null},"password":{"$ne":null}}` (NoSQLi)
- `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>` (XXE)

Blocked requests appear in the Admin Dashboard.