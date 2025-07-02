import sqlite3
import time
import jwt
import asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
from dotenv import load_dotenv
import os
from aiosmtpd.controller import Controller
from email.parser import BytesParser
from email.policy import default

load_dotenv()
BREVO_API_KEY = os.getenv("BREVO_API_KEY")  # Brevo API key

# === CONFIG ===
JWT_SECRET = "supersecretkey"  # Change this!
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 900  # 15 minutes
REFRESH_TOKEN_EXPIRE = 7 * 86400  # 7 days

app = Flask(__name__)
CORS(app)

# === DATABASE SETUP ===
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


# === Send email using Brevo REST API ===
def send_email_brevo(to_email, subject, body, from_email, from_name="Mystik Mailer"):
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }
    data = {
        "sender": {
            "name": from_name,
            "email": from_email
        },
        "to": [
            {
                "email": to_email
            }
        ],
        "subject": subject,
        "textContent": body
    }
    response = requests.post(url, json=data, headers=headers)
    if response.status_code not in (200, 201):
        raise Exception(f"Brevo API error {response.status_code}: {response.text}")


# === SMTP handler to receive emails ===
class EmailHandler:
    async def handle_DATA(self, server, session, envelope):
        raw_message = envelope.content
        email_message = BytesParser(policy=default).parsebytes(raw_message)

        sender = email_message.get("From")
        receiver = email_message.get("To")
        subject = email_message.get("Subject")

        # Extract plain text body
        body = ""
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    break
        else:
            body = email_message.get_payload(decode=True).decode(email_message.get_content_charset() or "utf-8",
                                                                 errors="replace")

        # Save email to DB
        db_conn.execute(
            "INSERT INTO emails (sender, receiver, subject, body, time) VALUES (?, ?, ?, ?, ?)",
            (sender, receiver, subject, body, int(time.time() * 1000))
        )
        db_conn.commit()

        print(f"[SMTP] Received email from {sender} to {receiver} subject: {subject}")

        return "250 Message accepted for delivery"


# === Flask API routes ===
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

    row = db_conn.execute("SELECT 1 FROM tokens WHERE user_email = ? AND refresh_token = ?", (email, token)).fetchone()
    if not row:
        return jsonify({"error": "Refresh token not recognized"}), 403

    new_access = generate_token(email, ACCESS_TOKEN_EXPIRE)
    return jsonify({"access_token": new_access})


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    db_conn.execute("DELETE FROM tokens WHERE user_email = ?", (request.user_email,))
    db_conn.commit()
    return jsonify({"message": "Logged out and tokens revoked"}), 200


@app.route("/users", methods=["GET"])
@token_required
def list_users():
    users = db_conn.execute("SELECT email FROM users").fetchall()
    return jsonify({"users": [user[0] for user in users]}), 200


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

    try:
        send_email_brevo(receiver, subject, body, sender)
    except Exception as e:
        return jsonify({"error": f"Failed to send via Brevo API: {str(e)}"}), 500

    return jsonify({"message": "Email sent and stored successfully"}), 200


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


# === Run both SMTP server and Flask app ===
async def run_smtp_server():
    controller = Controller(EmailHandler(), hostname="0.0.0.0", port=25)
    controller.start()
    print("[SMTP] Server running on port 25")


async def main():
    import hypercorn.asyncio
    from hypercorn.config import Config

    asyncio.create_task(run_smtp_server())

    config = Config()
    config.bind = ["0.0.0.0:5000"]
    await hypercorn.asyncio.serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
