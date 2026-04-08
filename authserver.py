# auth_server.py — ZipChat Auth Backend (Python/Flask)
# Install:  pip install flask flask-cors bcrypt pyjwt
# Run:      python auth_server.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import random
import time
import os

app = Flask(__name__)
CORS(app) #cross-origin resource sharing, without this, browsers would block requests from localhost8082 to 3000

SECRET     = "zipchat_supersecret_changeme"   # change in production
users      = {}    # { username: { password_hash, display_name } }
otp_store  = {}    # { username: { otp, expires } }

# ── REGISTER ─────────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data         = request.json
    username     = (data.get('username') or '').strip()
    password     = data.get('password') or ''
    display_name = (data.get('displayName') or username).strip()

    if not username or not password:
        return "Username and password required", 400
    if len(username) < 3:
        return "Username must be 3+ characters", 400
    if username in users:
        return "User exists", 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = { 'password_hash': pw_hash, 'display_name': display_name }
    print(f"[register] new user: {username} ({display_name})")
    return "User registered", 200

# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['POST']) #bcrypt.checkpw() re-hashes the submitted password with the stored salt and compares
def login():
    data     = request.json
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '')

    user = users.get(username)
    if not user:
        return "User not found", 401
    if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return "Wrong password", 401

    # Short-lived temp token (5 min) — only valid to call /send-otp and /verify-otp
    temp_token = jwt.encode(
        { 'username': username, 'exp': time.time() + 300 },
        SECRET, algorithm='HS256'
    )
    print(f"[login] password OK for {username}, awaiting OTP")
    return jsonify({ 'tempToken': temp_token })

# ── SEND OTP ──────────────────────────────────────────────────────────────────
@app.route('/send-otp', methods=['POST'])
def send_otp():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '')
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return "Temp token expired", 401
    except jwt.InvalidTokenError:
        return "Invalid temp token", 401

    username = decoded['username']
    otp      = str(random.randint(100000, 999999))
    expires  = time.time() + 300   # 5 minutes

    otp_store[username] = { 'otp': otp, 'expires': expires }

    # ── In production: send via email/SMS. For demo: print to console ──
    print(f"[OTP] {username} → {otp} (expires in 5 minutes)")
    return "OTP sent", 200

# ── VERIFY OTP ────────────────────────────────────────────────────────────────
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data     = request.json
    username = (data.get('username') or '').strip()
    otp      = str(data.get('otp') or '').strip()

    record = otp_store.get(username)
    if not record:
        return "No OTP requested for this user", 401
    if time.time() > record['expires']:
        del otp_store[username]
        return "OTP expired", 401
    if record['otp'] != otp:
        return "Invalid OTP", 401

    del otp_store[username]

    user = users[username]
    token = jwt.encode(
        {
            'username':    username,
            'displayName': user['display_name'],
            'exp':         time.time() + 86400  # 24 hours
        },
        SECRET, algorithm='HS256'
    )
    print(f"[verify-otp] MFA passed for {username}, issuing session token")
    return jsonify({ 'token': token, 'displayName': user['display_name'] })

# ── VERIFY TOKEN (called by server.js to authenticate WebSocket connections) ──
@app.route('/verify-token', methods=['POST'])
def verify_token():
    data  = request.json
    token = data.get('token') or ''
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
        return jsonify({
            'valid':       True,
            'username':    decoded['username'],
            'displayName': decoded.get('displayName', decoded['username'])
        })
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return jsonify({ 'valid': False }), 401

# ── RUN ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(port=3000, debug=True)