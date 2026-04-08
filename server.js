// server.js — ZipChat WebSocket Relay
// Verifies JWT via authServer before allowing any relay
// All frames logged to console AND zipchat_packets.log for Wireshark evidence

const WebSocket = require('ws');
const http      = require('http');
const fs        = require('fs');
const path      = require('path');

const WS_PORT   = 8082;
const AUTH_HOST = 'localhost';
const AUTH_PORT = 3000;

const wss = new WebSocket.Server({ port: WS_PORT });

// sessions: clientId → { ws, username, displayName, loggedIn }
const sessions = new Map();
let nextId     = 1;
let packetNum  = 0;

// Rate limit auth attempts — prevent reconnect spam
// ip → { count, firstSeen }
const authAttempts = new Map();
const AUTH_LIMIT   = 20;   // max auth attempts per IP per window
const AUTH_WINDOW  = 60000; // 60 seconds

// Add this near the top of server.js
http.get(`http://${AUTH_HOST}:${AUTH_PORT}/`, (res) => {
    console.log('[AUTH SERVER] reachable ✓');
}).on('error', () => {
    console.error('[AUTH SERVER] ⚠️  Not reachable at port', AUTH_PORT, '— token verification will fail!');
});

function isRateLimited(ip) {
  const now    = Date.now();
  const record = authAttempts.get(ip) || { count: 0, firstSeen: now };
  if (now - record.firstSeen > AUTH_WINDOW) {
    // Window expired — reset
    authAttempts.set(ip, { count: 1, firstSeen: now });
    return false;
  }
  record.count++;
  authAttempts.set(ip, record);
  if (record.count > AUTH_LIMIT) {
    console.log(`[RATE LIMIT] ${ip} blocked — ${record.count} auth attempts in ${AUTH_WINDOW}ms`);
    return true;
  }
  return false;
}

// ── Packet log file (written alongside server.js) ─────────────────────────────
const LOG_FILE = path.join(__dirname, 'zipchat_packets.log');
// Clear log on each server start so it stays fresh
fs.writeFileSync(LOG_FILE,
  '='.repeat(72) + '\n' +
  '  ZipChat WebSocket Packet Log\n' +
  '  Started: ' + new Date().toISOString() + '\n' +
  '  Port: ' + WS_PORT + '\n' +
  '='.repeat(72) + '\n\n'
);

// ── Core packet logger ────────────────────────────────────────────────────────
// Logs to BOTH terminal (colour) and zipchat_packets.log (plain text)
function logPacket(clientId, direction, msgType, details = {}) {
  packetNum++;
  const ts      = new Date().toISOString();
  const session = sessions.get(clientId);
  const user    = session?.username ?? '(unauth)';
  const arrow   = direction === 'IN' ? 'CLIENT → SERVER' : 'SERVER → CLIENT';

  // ── Classify the frame for Wireshark evidence ──────────────────────────────
  let classification = '';
  let encryptionNote = '';

  if (msgType === 'chat') {
    classification = '🔴 ENCRYPTED CHAT MESSAGE';
    encryptionNote = 'PLAINTEXT NOT VISIBLE — AES-256-GCM encrypted payload';
  } else if (msgType === 'relay:chat') {
    classification = '🔴 ENCRYPTED CHAT RELAY';
    encryptionNote = 'PLAINTEXT NOT VISIBLE — AES-256-GCM encrypted payload';
  } else if (msgType === 'kyber_pubkey' || msgType === 'relay:kyber_pubkey') {
    classification = '🟡 ML-KEM-768 PUBLIC KEY';
    encryptionNote = 'Public key only — safe to transmit, no secret exposed';
  } else if (msgType === 'kyber_ct' || msgType === 'relay:kyber_ct') {
    classification = '🟡 ML-KEM-768 CIPHERTEXT';
    encryptionNote = 'Encapsulated ciphertext — shared secret NOT derivable from this';
  } else if (msgType === 'kyber_hello') {
    classification = '🟢 KEY EXCHANGE INIT';
    encryptionNote = 'Handshake start — no secret data';
  } else if (msgType === 'auth_token') {
    classification = '🔵 JWT AUTH';
    encryptionNote = 'Signed JWT token — server verifies, no password in wire';
  } else if (msgType === 'auth_ok') {
    classification = '🟢 AUTH SUCCESS';
    encryptionNote = 'Login confirmed';
  } else {
    classification = '⚪ CONTROL FRAME';
    encryptionNote = 'Signalling only';
  }

  // ── Build safe details (truncate large byte arrays) ───────────────────────
  const safeDetails = {};
  for (const [k, v] of Object.entries(details)) {
    if (Array.isArray(v) && v.length > 8) {
      safeDetails[k] = `[${v.length} bytes — encrypted, not shown]`;
    } else {
      safeDetails[k] = v;
    }
  }

  // ── Terminal output (coloured) ─────────────────────────────────────────────
  const colours = {
    reset: '\x1b[0m', cyan: '\x1b[36m', yellow: '\x1b[33m',
    green: '\x1b[32m', red: '\x1b[31m', grey: '\x1b[90m', bold: '\x1b[1m'
  };
  console.log(
    `\n${colours.bold}${colours.cyan}[PKT #${packetNum}]${colours.reset} ${colours.grey}${ts}${colours.reset}` +
    `\n  ${colours.bold}${arrow}${colours.reset}` +
    `\n  Client: ${clientId} | User: ${colours.yellow}${user}${colours.reset}` +
    `\n  Type:   ${colours.bold}${msgType}${colours.reset}` +
    `\n  Class:  ${classification}` +
    `\n  Note:   ${colours.green}${encryptionNote}${colours.reset}` +
    (Object.keys(safeDetails).length ? `\n  Data:   ${JSON.stringify(safeDetails)}` : '')
  );

  // ── File output (plain text — open in any text editor or attach to report) ─
  const fileLine =
    `[PKT #${packetNum}] ${ts}\n` +
    `  Direction : ${arrow}\n` +
    `  Client ID : ${clientId}\n` +
    `  Username  : ${user}\n` +
    `  Msg Type  : ${msgType}\n` +
    `  Class     : ${classification}\n` +
    `  Enc Note  : ${encryptionNote}\n` +
    (Object.keys(safeDetails).length ? `  Payload   : ${JSON.stringify(safeDetails)}\n` : '') +
    '-'.repeat(72) + '\n';

  fs.appendFileSync(LOG_FILE, fileLine);
}

// ── Verify JWT with authServer ────────────────────────────────────────────────
function verifyToken(token) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ token });
    const req  = http.request(
      { host: AUTH_HOST, port: AUTH_PORT, path: '/verify-token', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve({ valid: false }); }
        });
      }
    );
    req.on('error', () => resolve({ valid: false }));
    req.write(body);
    req.end();
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function broadcastPresence() {
  const online = [];
  for (const [id, s] of sessions) {
    if (s.loggedIn) online.push({ clientId: id, username: s.username, displayName: s.displayName });
  }
  for (const [, s] of sessions) {
    if (s.loggedIn) send(s.ws, { type: 'presence_list', users: online });
  }
}

// ── Connection ────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const clientId = nextId++;
  const clientIp = req.socket.remoteAddress;
  sessions.set(clientId, { ws, username: null, displayName: null, loggedIn: false, ip: clientIp });

  const connLine =
    `\n${'='.repeat(72)}\n` +
    `[CONNECT] ${new Date().toISOString()}\n` +
    `  Client ID : ${clientId}\n` +
    `  IP        : ${clientIp}\n` +
    `  Total     : ${sessions.size} connected\n` +
    `${'='.repeat(72)}\n`;

  console.log(connLine);
  fs.appendFileSync(LOG_FILE, connLine);

  send(ws, { type: 'welcome', clientId });

  ws.on('message', async raw => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    const session = sessions.get(clientId);

    // ── JWT Auth ──────────────────────────────────────────────────────────────
    if (data.type === 'auth_token') {
      // Already authenticated — ignore duplicate auth attempts
      if (session.loggedIn) return;
      // Block if this IP is spamming auth attempts
      if (isRateLimited(session.ip || '127.0.0.1')) {
        ws.close();
        return;
      }
      logPacket(clientId, 'IN', 'auth_token', { tokenLength: data.token?.length });
      const result = await verifyToken(data.token);

      if (!result.valid) {
        logPacket(clientId, 'OUT', 'auth_failed', {});
        send(ws, { type: 'auth_failed', message: 'Invalid or expired token.' });
        return;
      }

      session.username    = result.username;
      session.displayName = result.displayName || result.username;
      session.loggedIn    = true;

      logPacket(clientId, 'OUT', 'auth_ok', { username: session.username });
      send(ws, { type: 'auth_ok', username: session.username, displayName: session.displayName });

      for (const [id, s] of sessions) {
        if (id !== clientId && s.loggedIn) {
          send(s.ws, { type: 'peer_joined', peerId: clientId,
            username: session.username, displayName: session.displayName });
          send(ws, { type: 'peer_joined', peerId: id,
            username: s.username, displayName: s.displayName });
        }
      }
      broadcastPresence();
      return;
    }

    // ── Require auth for all other frames ─────────────────────────────────────
    if (!session.loggedIn) {
      send(ws, { type: 'error', message: 'Not authenticated.' });
      return;
    }

    // ── Log incoming frame ────────────────────────────────────────────────────
    const inDetails = {};
    if (data.to)         inDetails.to         = data.to;
    if (data.cipherText) inDetails.cipherText  = data.cipherText;
    if (data.iv)         inDetails.iv          = data.iv;
    if (data.publicKey)  inDetails.publicKey   = data.publicKey;
    if (data.cipherText && !data.iv) inDetails.cipherText = data.cipherText; // kyber_ct
    logPacket(clientId, 'IN', data.type, inDetails);

    // ── Logout ────────────────────────────────────────────────────────────────
    if (data.type === 'logout') {
      for (const [id, s] of sessions) {
        if (id !== clientId && s.loggedIn)
          send(s.ws, { type: 'peer_left', peerId: clientId, username: session.username });
      }
      session.loggedIn = false; session.username = null; session.displayName = null;
      send(ws, { type: 'logout_ok' });
      broadcastPresence();
      return;
    }

    // ── Targeted relay ────────────────────────────────────────────────────────
    if (data.to) {
      for (const [id, s] of sessions) {
        if (id === data.to && s.loggedIn && s.ws.readyState === WebSocket.OPEN) {
          const relayType = 'relay:' + data.type;
          const relayDetails = {};
          if (data.cipherText) relayDetails.cipherText = data.cipherText;
          if (data.iv)         relayDetails.iv          = data.iv;
          if (data.publicKey)  relayDetails.publicKey   = data.publicKey;
          logPacket(clientId, 'OUT', relayType, {
            ...relayDetails,
            fromUser: session.username,
            toUser: s.username
          });
          s.ws.send(JSON.stringify({
            ...data,
            from:            clientId,
            fromUsername:    session.username,
            fromDisplayName: session.displayName,
          }));
        }
      }
    }
  });

  ws.on('close', () => {
    const session = sessions.get(clientId);
    const discLine =
      `\n[DISCONNECT] ${new Date().toISOString()}\n` +
      `  Client ID : ${clientId}  User: ${session?.username ?? '(unauth)'}\n` +
      '-'.repeat(72) + '\n';
    console.log(discLine);
    fs.appendFileSync(LOG_FILE, discLine);

    if (session?.loggedIn) {
      for (const [id, s] of sessions) {
        if (id !== clientId && s.loggedIn)
          send(s.ws, { type: 'peer_left', peerId: clientId, username: session.username });
      }
    }
    sessions.delete(clientId);
    broadcastPresence();
  });

  ws.on('error', err => console.error(`[ERROR] client:${clientId}`, err.message));
});

console.log(`ZipChat Relay :${WS_PORT} | Auth :${AUTH_PORT} | Logging to zipchat_packets.log`);