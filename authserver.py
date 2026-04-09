# ══════════════════════════════════════════════════════════════════════════════
#  ZipChat — Auth Backend (auth_server.py)
#
#  Security features:
#  ✅ 1. bcrypt password hashing
#  ✅ 2. Two-factor authentication (password + OTP)
#  ✅ 3. Short-lived temp tokens (5 min) + full session tokens (24hr)
#  ✅ 4. OTP rate limiting — lockout after 5 failed attempts
#  ✅ 5. Cryptographically secure OTP using secrets module
#  ✅ 6. JWT with HS256 — verify-token endpoint for WebSocket server
#
#  Install:  pip install flask flask-cors bcrypt pyjwt
#  Run:      python auth_server.py
# ══════════════════════════════════════════════════════════════════════════════

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import secrets   # ✅ SECURITY FIX — cryptographically secure random (replaces random.randint)
import time
import os

app = Flask(__name__)
CORS(app)

# ✅ SECURITY — Load SECRET from environment variable in production
# Set it with: export ZIPCHAT_SECRET="your-long-random-secret"
# Falls back to default for development only
SECRET = os.environ.get('ZIPCHAT_SECRET', 'zipchat_supersecret_changeme')

if SECRET == 'zipchat_supersecret_changeme':
    print('\n⚠️  WARNING: Using default JWT secret. Set ZIPCHAT_SECRET env var in production!\n')

# ── In-memory storage (replace with PostgreSQL/SQLite for production) ─────────
users      = {}   # { username: { password_hash, display_name } }
otp_store  = {}   # { username: { otp, expires, attempts } }

# ── REGISTER ──────────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data         = request.json or {}
    username     = (data.get('username') or '').strip().lower()
    password     = data.get('password') or ''
    display_name = (data.get('displayName') or username).strip()

    if not username or not password:
        return 'Username and password required', 400
    if len(username) < 3:
        return 'Username must be 3+ characters', 400
    if len(password) < 6:
        return 'Password must be 6+ characters', 400
    if username in users:
        return 'User exists', 400

    # ✅ bcrypt with cost factor 12 (intentionally slow — resists brute force)
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    users[username] = { 'password_hash': pw_hash, 'display_name': display_name }
    print(f'[register] new user: {username} ({display_name})')
    return 'User registered', 200


# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''

    user = users.get(username)
    if not user:
        # ✅ SECURITY — Same error message as wrong password (prevents user enumeration)
        return 'Invalid credentials', 401
    if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return 'Invalid credentials', 401

    # Short-lived temp token (5 min) — only valid for /send-otp + /verify-otp
    temp_token = jwt.encode(
        { 'username': username, 'exp': time.time() + 300, 'scope': 'otp_only' },
        SECRET, algorithm='HS256'
    )
    print(f'[login] password OK for {username}, awaiting OTP')
    return jsonify({ 'tempToken': temp_token })


# ── SEND OTP ──────────────────────────────────────────────────────────────────
@app.route('/send-otp', methods=['POST'])
def send_otp():
    token = _extract_bearer()
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Temp token expired', 401
    except jwt.InvalidTokenError:
        return 'Invalid temp token', 401

    # Verify this is a temp token, not a full session token
    if decoded.get('scope') != 'otp_only':
        return 'Invalid token scope', 401

    username = decoded['username']

    # ✅ SECURITY FIX — Use secrets module for cryptographically secure OTP
    # secrets.randbelow(900000) gives 0-899999, +100000 gives 100000-999999
    otp     = str(secrets.randbelow(900000) + 100000)
    expires = time.time() + 300   # 5 minutes

    # Reset attempts on new OTP request
    otp_store[username] = { 'otp': otp, 'expires': expires, 'attempts': 0 }

    # ── In production: send via email/SMS ──────────────────────────────────────
    # Email example: send_email(user_email, otp)
    # SMS example:   send_sms(user_phone, otp)
    # For demo: print to console
    print(f'\n┌─────────────────────────────────────┐')
    print(f'│  OTP for: {username:<25}│')
    print(f'│  Code:    {otp:<25}  │')
    print(f'│  Expires in 5 minutes               │')
    print(f'└─────────────────────────────────────┘\n')

    return 'OTP sent', 200


# ── VERIFY OTP ────────────────────────────────────────────────────────────────
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    otp      = str(data.get('otp') or '').strip()

    record = otp_store.get(username)
    if not record:
        return 'No OTP requested for this user', 401

    # ✅ SECURITY FIX — Rate limiting: lockout after 5 failed attempts
    if record.get('attempts', 0) >= 5:
        del otp_store[username]
        print(f'[verify-otp] LOCKOUT: {username} exceeded max OTP attempts')
        return 'Too many attempts — request a new OTP', 429

    if time.time() > record['expires']:
        del otp_store[username]
        return 'OTP expired', 401

    # ✅ SECURITY — Increment attempt counter BEFORE checking (prevents timing race)
    otp_store[username]['attempts'] = record.get('attempts', 0) + 1

    # ✅ SECURITY — Use secrets.compare_digest for timing-safe comparison
    # Prevents timing attacks where attacker measures response time
    if not secrets.compare_digest(record['otp'], otp):
        remaining = 5 - otp_store[username]['attempts']
        print(f'[verify-otp] wrong OTP for {username}, {remaining} attempts left')
        return f'Invalid OTP ({remaining} attempts remaining)', 401

    # OTP correct — consume it immediately (one-time use)
    del otp_store[username]

    user  = users[username]
    token = jwt.encode(
        {
            'username':    username,
            'displayName': user['display_name'],
            'exp':         time.time() + 86400,  # 24 hours
            'scope':       'session'
        },
        SECRET, algorithm='HS256'
    )
    print(f'[verify-otp] ✅ MFA passed for {username} — session token issued')
    return jsonify({ 'token': token, 'displayName': user['display_name'] })


# ── VERIFY TOKEN (called by server.js to authenticate WebSocket connections) ──
@app.route('/verify-token', methods=['POST'])
def verify_token():
    data  = request.json or {}
    token = data.get('token') or ''
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])

        # ✅ SECURITY — Reject temp tokens on WebSocket auth
        if decoded.get('scope') != 'session':
            return jsonify({ 'valid': False, 'reason': 'Not a session token' }), 401

        return jsonify({
            'valid':       True,
            'username':    decoded['username'],
            'displayName': decoded.get('displayName', decoded['username'])
        })
    except jwt.ExpiredSignatureError:
        return jsonify({ 'valid': False, 'reason': 'Token expired' }), 401
    except jwt.InvalidTokenError:
        return jsonify({ 'valid': False, 'reason': 'Invalid token' }), 401


# ── Utility ───────────────────────────────────────────────────────────────────
def _extract_bearer():
    auth = request.headers.get('Authorization', '')
    return auth.replace('Bearer ', '').strip()


# ── RUN ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('\n┌─────────────────────────────────────────────┐')
    print('│  ZipChat Auth Server                        │')
    print('│  Running on http://localhost:3000           │')
    print('│  Endpoints:                                 │')
    print('│    POST /register                           │')
    print('│    POST /login                              │')
    print('│    POST /send-otp                           │')
    print('│    POST /verify-otp                         │')
    print('│    POST /verify-token                       │')
    print('└─────────────────────────────────────────────┘\n')
    # ✅ SECURITY — debug=False in production
    app.run(port=3000, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')