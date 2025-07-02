import sqlite3
import time
import jwt
import asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from aiosmtpd.controller import Controller
from email.parser import BytesParser
from email.policy import default
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


# === CONFIG ===
JWT_SECRET = "supersecretkey"  # Change this!
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 900       # 15 minutes
REFRESH_TOKEN_EXPIRE = 7 * 86400  # 7 days
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_USERNAME = "apikey"  # DO NOT change this
FROM_NAME = "Mystik Mailer"


app = Flask(__name__)
CORS(app)  # Allow all origins for development

# === DATABASE ===
db_conn = sqlite3.connect("email_server.db", check_same_thread=False)
db_conn.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
)
''')

db_conn.execute('''
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    subject TEXT,
    body TEXT,
    time INTEGER
)
''')

db_conn.execute('''
CREATE TABLE IF NOT EXISTS tokens (
    user_email TEXT,
    refresh_token TEXT,
    expires_at INTEGER
)
''')

db_conn.commit()

# === JWT HELPERS ===
def generate_token(email, expire_seconds, is_refresh=False):
    payload = {
        "email": email,
        "exp": time.time() + expire_seconds,
        "type": "refresh" if is_refresh else "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[-1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if data.get("type") != "access":
                return jsonify({"error": "Invalid access token"}), 403
            request.user_email = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return wrapper


def send_email_brevo(to_email, subject, body, from_email):
    msg = MIMEMultipart()
    msg["From"] = f"{FROM_NAME} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


# === REGISTER ===
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if "@" in username:
        return jsonify({"error": "Username must not contain @"}), 400

    email = f"{username}@mystik.lol"

    if db_conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"error": "Email already registered"}), 400

    hashed_pw = generate_password_hash(password)
    db_conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw))
    db_conn.commit()
    return jsonify({"message": f"User {email} registered successfully"}), 200

# === LOGIN ===
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    row = db_conn.execute("SELECT password FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not check_password_hash(row[0], password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = generate_token(email, ACCESS_TOKEN_EXPIRE)
    refresh_token = generate_token(email, REFRESH_TOKEN_EXPIRE, is_refresh=True)

    db_conn.execute("INSERT INTO tokens (user_email, refresh_token, expires_at) VALUES (?, ?, ?)",
                    (email, refresh_token, int(time.time() + REFRESH_TOKEN_EXPIRE)))
    db_conn.commit()

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    })

# === REFRESH TOKEN ===
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    token = data.get("refresh_token", "")

    if not token:
        return jsonify({"error": "Refresh token required"}), 400

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "refresh":
            return jsonify({"error": "Invalid refresh token"}), 400
        email = decoded["email"]
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 400

    # Check token exists in DB
    row = db_conn.execute("SELECT 1 FROM tokens WHERE user_email = ? AND refresh_token = ?", (email, token)).fetchone()
    if not row:
        return jsonify({"error": "Refresh token not recognized"}), 403

    # Generate new access token
    new_access = generate_token(email, ACCESS_TOKEN_EXPIRE)
    return jsonify({"access_token": new_access})

# === LOGOUT ===
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    db_conn.execute("DELETE FROM tokens WHERE user_email = ?", (request.user_email,))
    db_conn.commit()
    return jsonify({"message": "Logged out and tokens revoked"}), 200

# === LIST USERS ===
@app.route("/users", methods=["GET"])
@token_required
def list_users():
    users = db_conn.execute("SELECT email FROM users").fetchall()
    return jsonify({"users": [user[0] for user in users]}), 200

# === SEND EMAIL ===
@app.route("/send_email", methods=["POST"])
@token_required
def send_email():
    data = request.json
    sender = request.user_email
    receiver = data.get("receiver")
    subject = data.get("subject", "")
    body = data.get("body", "")

    if not receiver:
        return jsonify({"error": "Receiver is required"}), 400

    # Save to DB
    db_conn.execute(
        "INSERT INTO emails (sender, receiver, subject, body, time) VALUES (?, ?, ?, ?, ?)",
        (sender, receiver, subject, body, int(time.time() * 1000))
    )
    db_conn.commit()

    # Send actual email via Brevo
    try:
        send_email_brevo(receiver, subject, body, sender)
    except Exception as e:
        return jsonify({"error": f"Failed to send via SMTP: {str(e)}"}), 500

    return jsonify({"message": "Email sent and stored successfully"}), 200


# === FETCH EMAILS ===
@app.route("/emails/<username>", methods=["GET"])
@token_required
def get_emails(username):
    email = f"{username}@mystik.lol"
    if request.user_email != email:
        return jsonify({"error": "Unauthorized access"}), 403

    emails = db_conn.execute(
        "SELECT sender, subject, body, time FROM emails WHERE receiver = ? ORDER BY time DESC",
        (email,)
    ).fetchall()

    return jsonify({
        "inbox": [
            {"from": e[0], "subject": e[1], "body": e[2], "timestamp": e[3]} for e in emails
        ]
    })

# === EMAIL BODY HELPER ===
def get_email_body(email_message):
    if email_message.is_multipart():
        # Loop through parts and get the plain text one
        for part in email_message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        # If no plain text part found, fallback to first part
        first_part = email_message.get_payload(0)
        payload = first_part.get_payload(decode=True)
        if payload:
            return payload.decode(first_part.get_content_charset() or "utf-8", errors="replace")
        return ""
    else:
        payload = email_message.get_payload(decode=True)
        if payload:
            return payload.decode(email_message.get_content_charset() or "utf-8", errors="replace")
        return ""

# === SMTP SERVER ===
class EmailHandler:
    async def handle_DATA(self, server, session, envelope):
        email_message = await self.parse_email(envelope.content)
        sender = email_message.get("From")
        receiver = email_message.get("To")
        subject = email_message.get("Subject")
        body = get_email_body(email_message)

        print(f"[SMTP] {sender} -> {receiver}")
        try:
            self.save_to_db(sender, receiver, subject, body)
            print("[SMTP] Email saved.")
        except Exception as e:
            print(f"[SMTP] Error saving email: {e}")

        return "250 OK"

    async def parse_email(self, content):
        return BytesParser(policy=default).parsebytes(content)

    def save_to_db(self, sender, receiver, subject, body):
        db_conn.execute(
            "INSERT INTO emails (sender, receiver, subject, body, time) VALUES (?, ?, ?, ?, ?)",
            (sender, receiver, subject, body, int(time.time() * 1000))
        )
        db_conn.commit()

async def run_smtp():
    controller = Controller(EmailHandler(), hostname="0.0.0.0", port=25)
    controller.start()
    print("[SMTP] Server running on port 8025")

# === COMBINED SERVER ===
async def main():
    asyncio.create_task(run_smtp())
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    config = Config()
    config.bind = ["0.0.0.0:5000"]
    await serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())
