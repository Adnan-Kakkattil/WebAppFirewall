# WebAppFirewall (Python + Flask)

A lightweight Web Application Firewall (WAF) built in Python.  
It runs as a middleware layer in Flask and blocks suspicious requests before they reach app routes.

## Features

- Regex-based detection for:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Path Traversal and Command Injection patterns
- `@app.before_request` inspection layer
- Automatic blocking with `403 Forbidden`
- SQLite logging of blocked attacks:
  - timestamp, IP, attack type, method, path, payload
- Request monitoring for all incoming traffic:
  - allowed/blocked status, path, method, detected type
- Admin authentication with hashed passwords
- Admin dashboard for attack summaries and recent logs
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

- Username: `admin`
- Password: `admin123`

You can override with environment variables:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `APP_SECRET`

## Demo Payloads

Try these in Simulation Mode:

- `<script>alert(1)</script>` (XSS)
- `' OR '1'='1` (SQLi)
- `UNION SELECT password FROM users` (SQLi)

Blocked requests appear in the Admin Dashboard.