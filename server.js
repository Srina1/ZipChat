// ══════════════════════════════════════════════════════════════════════════════
//  ZipChat — WebSocket Server (server.js)
//
//  Security features:
//  ✅ 1. WSS — WebSocket over TLS (wss://)
//  ✅ 2. JWT token verification via auth_server.py
//  ✅ 3. Peer relay only — server never sees plaintext
//  ✅ 4. Dummy traffic pass-through support
//
//  Install:  npm install ws
//  TLS cert: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
//  Run:      node server.js
// ══════════════════════════════════════════════════════════════════════════════

const https  = require('https');
const fs     = require('fs');
const http   = require('http');
const { WebSocketServer } = require('ws');
const fetch  = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const AUTH_URL = 'http://localhost:3000/verify-token';
const PORT     = 8082;

// ══════════════════════════════════════════════════════════════════════════════
//  ✅ SECURITY 1 — WSS: Create HTTPS server with TLS certificate
//
//  Option A (Production):  Use real cert from Let's Encrypt
//  Option B (Development): Use self-signed cert (generated with openssl above)
//
//  If cert.pem / key.pem don't exist yet, the server falls back to plain ws://
//  so you can still develop. Replace with real certs for production.
// ══════════════════════════════════════════════════════════════════════════════

let server;
let usingTLS = false;

try {
    const tlsOptions = {
        cert: fs.readFileSync('cert.pem'),
        key:  fs.readFileSync('key.pem')
    };
    server   = https.createServer(tlsOptions);
    usingTLS = true;
    console.log('✅ TLS certificates loaded — using WSS (wss://)');
} catch (e) {
    console.warn('⚠️  cert.pem / key.pem not found — falling back to WS (ws://)');
    console.warn('   Generate with: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes');
    server = http.createServer();
}

const wss = new WebSocketServer({ server });

// ── State ─────────────────────────────────────────────────────────────────────
let clientIdCounter = 1;
// rooms: chatId → Map(clientId → { ws, username, displayName })
const rooms = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────
function getRoomClients(chatId) {
    if (!rooms.has(chatId)) rooms.set(chatId, new Map());
    return rooms.get(chatId);
}

function broadcast(chatId, data, excludeId = null) {
    const clients = getRoomClients(chatId);
    const msg     = JSON.stringify(data);
    for (const [id, client] of clients) {
        if (id !== excludeId && client.ws.readyState === 1) {
            client.ws.send(msg);
        }
    }
}

function sendTo(clientId, chatId, data) {
    const clients = getRoomClients(chatId);
    const client  = clients.get(clientId);
    if (client && client.ws.readyState === 1) {
        client.ws.send(JSON.stringify(data));
    }
}

// ── Connection handler ────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
    const clientId = clientIdCounter++;
    let   username    = null;
    let   displayName = null;
    let   chatId      = null;
    let   authed      = false;

    // Extract chatId from URL: wss://host:8082/?chat=roomname
    const urlParams = new URL(req.url, 'wss://localhost:8082');
    chatId = (urlParams.searchParams.get('chat') || 'public').replace(/[.#$[\]]/g,'_');

    console.log(`[connect] client ${clientId} → room: ${chatId} | TLS: ${usingTLS}`);

    ws.send(JSON.stringify({ type: 'welcome', clientId }));

    const authTimeout = setTimeout(() => {
        if (!authed) {
            console.log(`[timeout] client ${clientId} did not authenticate`);
            ws.close();
        }
    }, 10000); // 10s to authenticate

    ws.on('message', async (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // ── Auth ──────────────────────────────────────────────────────────────
        if (data.type === 'auth_token') {
            try {
                const res  = await fetch(AUTH_URL, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ token: data.token })
                });
                const body = await res.json();

                if (!body.valid) {
                    ws.send(JSON.stringify({ type: 'auth_failed' }));
                    ws.close();
                    return;
                }

                clearTimeout(authTimeout);
                authed      = true;
                username    = body.username;
                displayName = body.displayName;

                const clients = getRoomClients(chatId);
                clients.set(clientId, { ws, username, displayName });

                ws.send(JSON.stringify({ type: 'auth_ok', clientId }));

                // Notify existing peers
                for (const [peerId, peer] of clients) {
                    if (peerId === clientId) continue;
                    // Tell new client about existing peer
                    ws.send(JSON.stringify({
                        type: 'peer_joined', peerId, chatId,
                        username:    peer.username,
                        displayName: peer.displayName
                    }));
                    // Tell existing peer about new client
                    peer.ws.send(JSON.stringify({
                        type: 'peer_joined', peerId: clientId, chatId,
                        username, displayName
                    }));
                }

                console.log(`[auth_ok] ${username} (${displayName}) → room: ${chatId}`);

            } catch (e) {
                console.error('[auth error]', e.message);
                ws.send(JSON.stringify({ type: 'auth_failed' }));
                ws.close();
            }
            return;
        }

        if (!authed) return; // ignore all messages until authenticated

        // ── Relay messages to target peer ─────────────────────────────────────
        // Handles: kyber_hello, kyber_pubkey, kyber_ct,
        //          dsa_pubkey (NEW), chat, dummy (NEW)
        if (data.to) {
            const clients = getRoomClients(chatId);
            const target  = clients.get(data.to);
            if (target && target.ws.readyState === 1) {
                target.ws.send(JSON.stringify({
                    ...data,
                    from:        clientId,
                    fromUsername: username,
                    type:        'relay:' + data.type
                }));
            }
            return;
        }
    });

    ws.on('close', () => {
        if (!chatId) return;
        const clients = getRoomClients(chatId);
        clients.delete(clientId);

        if (authed) {
            broadcast(chatId, { type: 'peer_left', peerId: clientId }, clientId);
            console.log(`[disconnect] ${username} left room: ${chatId}`);
        }

        if (clients.size === 0) rooms.delete(chatId);
    });

    ws.on('error', (err) => {
        console.error(`[ws error] client ${clientId}:`, err.message);
    });
});

// ── Start ─────────────────────────────────────────────────────────────────────
server.listen(PORT, () => {
    const proto = usingTLS ? 'wss' : 'ws';
    console.log(`\n┌─────────────────────────────────────────────┐`);
    console.log(`│  ZipChat WebSocket Server                   │`);
    console.log(`│  Listening on ${proto}://localhost:${PORT}         │`);
    console.log(`│  TLS/WSS: ${usingTLS ? '✅ ENABLED              ' : '❌ DISABLED (dev mode) '}        │`);
    console.log(`│  Auth:    http://localhost:3000/verify-token │`);
    console.log(`└─────────────────────────────────────────────┘\n`);
});