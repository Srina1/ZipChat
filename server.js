// ══════════════════════════════════════════════════════════════════════════════
//  ZipChat — WebSocket Server (server.js)
//
//  ✅ WSS (wss://) — WebSocket over TLS
//  ✅ JWT auth via auth_server.py
//  ✅ Relay-only — server never sees plaintext
//  ✅ Auth timeout — unauthenticated connections closed after 10s
//  ✅ FIX: auth_ok now sends clientId so client myId stays in sync
//
//  Install:  npm install ws node-fetch
//  TLS cert: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
//  Run:      node server.js
// ══════════════════════════════════════════════════════════════════════════════

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const { WebSocketServer } = require('ws');
const fetch  = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const AUTH_URL = 'http://localhost:3000/verify-token';
const PORT     = 8082;

let server;
let usingTLS = false;

try {
    server   = https.createServer({ cert: fs.readFileSync('cert.pem'), key: fs.readFileSync('key.pem') });
    usingTLS = true;
    console.log('✅ TLS loaded — WSS enabled');
} catch (e) {
    console.warn('⚠️  No cert.pem/key.pem — falling back to ws://');
    server = http.createServer();
}

const wss = new WebSocketServer({ server });
let clientIdCounter = 1;
const rooms = new Map();

function getRoomClients(chatId) {
    if (!rooms.has(chatId)) rooms.set(chatId, new Map());
    return rooms.get(chatId);
}

wss.on('connection', (ws, req) => {
    const clientId = clientIdCounter++;
    let username = null, displayName = null, chatId = null, authed = false;

    try {
        const u = new URL(req.url, `${usingTLS?'wss':'ws'}://localhost:${PORT}`);
        chatId  = (u.searchParams.get('chat') || 'public').replace(/[.#$[\]]/g, '_');
    } catch { chatId = 'public'; }

    console.log(`[connect] client ${clientId} → room: ${chatId}`);

    // FIX: Send clientId in welcome so client sets myId immediately and correctly
    ws.send(JSON.stringify({ type: 'welcome', clientId }));

    const authTimeout = setTimeout(() => { if (!authed) ws.close(); }, 10000);

    ws.on('message', async (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        if (data.type === 'auth_token') {
            try {
                const res  = await fetch(AUTH_URL, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: data.token })
                });
                const body = await res.json();
                if (!body.valid) { ws.send(JSON.stringify({ type: 'auth_failed' })); ws.close(); return; }

                clearTimeout(authTimeout);
                authed = true; username = body.username; displayName = body.displayName;

                const clients = getRoomClients(chatId);
                clients.set(clientId, { ws, username, displayName });

                // FIX: Include clientId in auth_ok so client can re-confirm myId
                ws.send(JSON.stringify({ type: 'auth_ok', clientId }));

                for (const [peerId, peer] of clients) {
                    if (peerId === clientId) continue;
                    ws.send(JSON.stringify({ type:'peer_joined', peerId, chatId, username: peer.username, displayName: peer.displayName }));
                    peer.ws.send(JSON.stringify({ type:'peer_joined', peerId: clientId, chatId, username, displayName }));
                }
                console.log(`[auth_ok] ${username} (id:${clientId}) → room: ${chatId}`);
            } catch (e) {
                console.error('[auth error]', e.message);
                ws.send(JSON.stringify({ type: 'auth_failed' })); ws.close();
            }
            return;
        }

        if (!authed) return;

        if (data.to) {
            const target = getRoomClients(chatId).get(data.to);
            if (target && target.ws.readyState === 1) {
                target.ws.send(JSON.stringify({ ...data, from: clientId, fromUsername: username, type: 'relay:' + data.type }));
            }
        }
    });

    ws.on('close', () => {
        if (!chatId) return;
        const clients = getRoomClients(chatId);
        clients.delete(clientId);
        if (authed) {
            for (const [, peer] of clients) {
                if (peer.ws.readyState === 1)
                    peer.ws.send(JSON.stringify({ type: 'peer_left', peerId: clientId }));
            }
            console.log(`[disconnect] ${username} left ${chatId}`);
        }
        if (clients.size === 0) rooms.delete(chatId);
    });

    ws.on('error', err => console.error(`[ws error] ${clientId}:`, err.message));
});

server.listen(PORT, () => {
    console.log(`ZipChat WebSocket Server running at ${usingTLS ? 'wss' : 'ws'}://localhost:${PORT}`);
    console.log(`TLS: ${usingTLS ? 'ENABLED' : 'DISABLED (dev)'}`);
});