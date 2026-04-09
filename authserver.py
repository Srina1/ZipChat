# ══════════════════════════════════════════════════════════════════════════════
#  ZipChat — Auth Backend (auth_server.py) — FINAL VERSION
#
#  Security features:
#  ✅ 1. bcrypt password hashing (rounds=12)
#  ✅ 2. Two-factor authentication — password + OTP
#  ✅ 3. Short-lived temp tokens (5 min) + full session tokens (24hr)
#  ✅ 4. OTP rate limiting — lockout after 5 failed attempts
#  ✅ 5. Cryptographically secure OTP — secrets module (not random)
#  ✅ 6. Timing-safe OTP comparison — secrets.compare_digest
#  ✅ 7. Token scope enforcement — temp tokens rejected at /verify-token
#  ✅ 8. User enumeration protection — same error for bad user + bad password
#
#  Install:  pip install flask flask-cors bcrypt pyjwt
#  Run:      python auth_server.py
# ══════════════════════════════════════════════════════════════════════════════

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import secrets
import time
import os

app = Flask(__name__)
CORS(app)

SECRET = os.environ.get('ZIPCHAT_SECRET', 'zipchat_supersecret_changeme')
if SECRET == 'zipchat_supersecret_changeme':
    print('\n⚠️  WARNING: Using default JWT secret! Set ZIPCHAT_SECRET env var in production.\n')

users     = {}
otp_store = {}

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
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    users[username] = { 'password_hash': pw_hash, 'display_name': display_name }
    print(f'[register] new user: {username} ({display_name})')
    return 'User registered', 200

@app.route('/login', methods=['POST'])
def login():
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    user     = users.get(username)
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return 'Invalid credentials', 401
    temp_token = jwt.encode(
        { 'username': username, 'exp': time.time() + 300, 'scope': 'otp_only' },
        SECRET, algorithm='HS256'
    )
    print(f'[login] password OK for {username}, awaiting OTP')
    return jsonify({ 'tempToken': temp_token })

@app.route('/send-otp', methods=['POST'])
def send_otp():
    token = _extract_bearer()
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return 'Temp token expired', 401
    except jwt.InvalidTokenError:
        return 'Invalid temp token', 401
    if decoded.get('scope') != 'otp_only':
        return 'Invalid token scope', 401
    username = decoded['username']
    otp      = str(secrets.randbelow(900000) + 100000)
    expires  = time.time() + 300
    otp_store[username] = { 'otp': otp, 'expires': expires, 'attempts': 0 }
    print(f'\n┌─────────────────────────────────────┐')
    print(f'│  OTP for:  {username:<24} │')
    print(f'│  Code:     {otp:<24} │')
    print(f'│  Expires in 5 minutes               │')
    print(f'└─────────────────────────────────────┘\n')
    return 'OTP sent', 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data     = request.json or {}
    username = (data.get('username') or '').strip().lower()
    otp      = str(data.get('otp') or '').strip()
    record   = otp_store.get(username)
    if not record:
        return 'No OTP requested for this user', 401
    if record.get('attempts', 0) >= 5:
        del otp_store[username]
        print(f'[verify-otp] LOCKOUT: {username}')
        return 'Too many attempts — request a new OTP', 429
    if time.time() > record['expires']:
        del otp_store[username]
        return 'OTP expired', 401
    otp_store[username]['attempts'] = record.get('attempts', 0) + 1
    if not secrets.compare_digest(record['otp'], otp):
        remaining = 5 - otp_store[username]['attempts']
        return f'Invalid OTP ({remaining} attempts remaining)', 401
    del otp_store[username]
    user  = users[username]
    token = jwt.encode(
        { 'username': username, 'displayName': user['display_name'],
          'exp': time.time() + 86400, 'scope': 'session' },
        SECRET, algorithm='HS256'
    )
    print(f'[verify-otp] ✅ MFA passed for {username}')
    return jsonify({ 'token': token, 'displayName': user['display_name'] })

@app.route('/verify-token', methods=['POST'])
def verify_token():
    data  = request.json or {}
    token = data.get('token') or ''
    try:
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
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

def _extract_bearer():
    auth = request.headers.get('Authorization', '')
    return auth.replace('Bearer ', '').strip()

if __name__ == '__main__':
    print('\n┌─────────────────────────────────────────────┐')
    print('│  ZipChat Auth Server — FINAL VERSION        │')
    print('│  http://localhost:3000                      │')
    print('└─────────────────────────────────────────────┘\n')
    app.run(port=3000, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')