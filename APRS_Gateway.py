import socket
import logging
import logging.handlers
import os
import re
from markupsafe import escape
from flask import Flask, render_template_string, request, flash, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "aprs-secret-key")
csrf = CSRFProtect(app)

# --- RATE LIMITING ---
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    app=app
)

# --- CONFIGURATION ---
APRS_SERVER = os.environ.get("APRS_SERVER", "rotate.aprs2.net")
APRS_PORT = int(os.environ.get("APRS_PORT", "14580"))
LOG_SERVER = os.environ.get("LOG_SERVER", None)  # Format: "ip:port" or None

# --- LOGGING SETUP ---
logger = logging.getLogger("APRS-Gateway")
logger.setLevel(logging.INFO)

# Console logging (for container logs)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# ---- Validation / Sanitization helpers ----

CALLSIGN_MAX_LEN = 9   # APRS destination field uses 9 chars max
MESSAGE_MAX_LEN = 67   # APRS message payload limit

_callsign_re = re.compile(r'^[A-Z0-9/]+(?:-[0-9]{1,2})?$')  # coarse check

# Syslog logging (if LOG_SERVER is configured)
if LOG_SERVER:
    try:
        log_host, log_port = LOG_SERVER.split(":")
        syslog_handler = logging.handlers.SysLogHandler(address=(log_host, int(log_port)))
        syslog_handler.setFormatter(logging.Formatter('APRS-Gateway: %(message)s'))
        logger.addHandler(syslog_handler)
        logger.info(f"Syslog enabled: {log_host}:{log_port}")
    except Exception as e:
        logger.error(f"Failed to configure syslog: {e}")

# --- HTML TEMPLATE ---
HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Local APRS-IS Message Gateway</title>
    <style>
        body { font-family: monospace; background-color: #f0f0f0; padding: 20px; }
        .container { background: white; border: 1px solid #ccc; padding: 20px; max-width: 600px; }
        input, textarea { margin-bottom: 10px; width: 100%; box-sizing: border-box; }
        label { font-weight: bold; }
        .error { color: red; }
        .success { color: green; }
        .warning { color: orange; font-weight: bold; }
        .tos { font-size: 0.9em; color: #555; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>APRS Message Entry</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <p class="{{ category }}">{{ message }}</p>
            {% endfor %}
          {% endif %}
        {% endwith %}
        
        <p class="warning">⚠️ This service is for licensed amateur radio operators only.</p>
        
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            
            <label>Your Callsign (with SSID):</label><br>
            <input type="text" name="source_call" placeholder="e.g. N0CALL-10" required><br>
            
            <label>Your APRS-IS Passcode:</label><br>
            <input type="password" name="passcode" placeholder="e.g. 6666" required><br>
            
            <label>To Callsign:</label><br>
            <input type="text" name="dest_call" placeholder="e.g. NI6V-1" required><br>
            
            <label>Message (max 67 chars):</label><br>
            <textarea name="message" rows="3" maxlength="67" required></textarea><br>
            
            <input type="submit" value="Send Message to APRS-IS">
        </form>

        <div class="tos">
            <p><strong>Terms of Use:</strong></p>
            <p>By selecting "Send Message to APRS-IS", you certify that:</p>
            <ul>
                <li>You are a licensed amateur radio operator.</li>
                <li>You are authorized to use the callsign and passcode provided.</li>
                <li>You understand that your IP address will be logged for security and audit purposes.</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
# ---- HTTP security headers ----

@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    # Minimal CSP: allow only same-origin resources; adjust if you load external assets
    response.headers.setdefault("Content-Security-Policy", "default-src 'self';")
    return response

def send_to_aprs_is(source_call, passcode, dest_call, message_text):
    """Handles the TCP connection and packet injection."""
    # APRS Message Format: SOURCE>APRS,TCPIP*::DESTINATION:MESSAGE
    # Destination callsign field in the message body must be 9 chars (padded with spaces)
    dest_padded = dest_call.ljust(CALLSIGN_MAX_LEN)
    packet = f"{source_call}>APRS,TCPIP*::{dest_padded}:{message_text}\n"
    
    try:
        # Create socket and connect
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((APRS_SERVER, APRS_PORT))
        
        # Read server banner
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        
        # Login
        login_str = f"user {source_call} pass {passcode} vers LocalGateway 1.0\n"
        s.sendall(login_str.encode('utf-8'))
        
        # Read login response
        response = s.recv(1024).decode('utf-8', errors='ignore')
        
        # Check if login was successful
        if "unverified" in response.lower():
            s.close()
            logger.warning(f"Failed login attempt from {source_call}")
            return False, "Login failed: Invalid passcode or callsign"
        
        # Send the packet
        s.sendall(packet.encode('utf-8'))
        s.close()
        
        # Log successful message
        logger.info(f"Message sent: {source_call} -> {dest_call}: {message_text}")
        
        return True, f"Message sent successfully to {dest_call}!"
    except socket.timeout:
        logger.error(f"Connection timeout for {source_call} -> {dest_call}")
        return False, "Connection timeout - check your network"
    except Exception as e:
        logger.error(f"Error sending message from {source_call} to {dest_call}: {str(e)}")
        return False, f"Error: {str(e)}"

def validate_callsign(raw: str) -> str | None:
    """
    Return normalized uppercase callsign if valid, otherwise None.
    Accepts callsigns containing letters/digits and optional single or multi-part
    prefixes separated by '/' and an optional SSID like -1..-15.
    """
    if not raw:
        return None
    s = raw.strip().upper()
    if len(s) > CALLSIGN_MAX_LEN:
        return None
    if not _callsign_re.match(s):
        return None
    # reject leading/trailing slash, double slashes, or empty segments
    if '//' in s or s.startswith('/') or s.endswith('/'):
        return None
    # ensure each slash-segment contains only alnum (and optional SSID)
    for seg in s.split('/'):
        if not seg:
            return None
        # allow segment like CALL or CALL-1
        if not re.match(r'^[A-Z0-9]+(?:-[0-9]{1,2})?$', seg):
            return None
    return s

def validate_passcode(raw: str) -> str | None:
    """
    APRS passcodes are normally numeric. Accept 1-10 digits conservatively.
    """
    if not raw:
        return None
    s = raw.strip()
    if not re.fullmatch(r'\d{1,10}', s):
        return None
    return s

def sanitize_message(raw: str) -> str | None:
    """
    Return sanitized message suitable for APRS:
    - Strip control chars and collapse whitespace/newlines to single spaces
    - Trim to MESSAGE_MAX_LEN chars
    - Return None if empty after sanitization
    """
    if raw is None:
        return None
    # remove non-printable/control characters except basic whitespace
    # keep printable characters and replace newlines/tabs with spaces
    cleaned = re.sub(r'[\r\n\t]+', ' ', raw)
    cleaned = ''.join(ch for ch in cleaned if ch.isprintable())
    # collapse multiple spaces to one
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    if not cleaned:
        return None
    # enforce APRS length
    if len(cleaned) > MESSAGE_MAX_LEN:
        cleaned = cleaned[:MESSAGE_MAX_LEN]
    return cleaned

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def index():
    if request.method == "POST":
        raw_source = request.form.get("source_call", "")
        raw_passcode = request.form.get("passcode", "")
        raw_dest = request.form.get("dest_call", "")
        raw_msg = request.form.get("message", "")

        source = validate_callsign(raw_source)
        passcode = validate_passcode(raw_passcode)
        dest = validate_callsign(raw_dest)
        msg = sanitize_message(raw_msg)

        # Get the user's IP address
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)

        if not source:
            flash("Invalid source callsign.", "error")
            return redirect(url_for("index"))
        if not passcode:
            flash("Invalid passcode format.", "error")
            return redirect(url_for("index"))
        if not dest:
            flash("Invalid destination callsign.", "error")
            return redirect(url_for("index"))
        if not msg:
            flash("Message is empty after sanitization.", "error")
            return redirect(url_for("index"))

        # Log the IP address along with the message attempt
        logger.info("Message attempt from IP %s: %s -> %s", user_ip, source, dest)

        success, status = send_to_aprs_is(source, passcode, dest, msg)

        if success:
            logger.info("Message sent from IP %s: %s -> %s: %s", user_ip, source, dest, msg)
            flash("Message sent successfully to " + escape(dest), "success")
        else:
            logger.warning("Message failed from IP %s: %s", user_ip, status)
            flash("Send failed: " + escape(status), "error")

        return redirect(url_for("index"))

    return render_template_string(HTML_FORM)
if __name__ == "__main__":
    app.run()