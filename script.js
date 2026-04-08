// ─────────────────────────────────────────────
// CONNECT (with optional token)
// ─────────────────────────────────────────────
const token = "test123"; // change if using real JWT
const ws = new WebSocket(`ws://localhost:8080?token=${token}`);

let myId = null;
const peerKeys = new Map();

// ─────────────────────────────────────────────
// ROLE DECISION
// ─────────────────────────────────────────────
function amInitiator(peerId) {
  return myId < peerId;
}

// ─────────────────────────────────────────────
// KYBER SIMULATION
// ─────────────────────────────────────────────
async function generateSharedSecret() {
  const rawSecret = crypto.getRandomValues(new Uint8Array(32));
  const secretBuf = await crypto.subtle.digest('SHA-256', rawSecret);
  return { rawSecret, sharedSecret: new Uint8Array(secretBuf) };
}

async function deriveSharedSecret(rawSecretArray) {
  const rawSecret = new Uint8Array(rawSecretArray);
  const secretBuf = await crypto.subtle.digest('SHA-256', rawSecret);
  return new Uint8Array(secretBuf);
}

// ─────────────────────────────────────────────
// STORE KEY
// ─────────────────────────────────────────────
async function storePeerSecret(peerId, sharedSecretBytes) {
  if (peerKeys.has(peerId)) return;

  const keyBytes = new Uint8Array(sharedSecretBytes);

  const encryptKey = await crypto.subtle.importKey(
    'raw', keyBytes, 'AES-GCM', false, ['encrypt']
  );

  const decryptKey = await crypto.subtle.importKey(
    'raw', keyBytes, 'AES-GCM', false, ['decrypt']
  );

  peerKeys.set(peerId, { encryptKey, decryptKey });
  console.log(`[key] Stored key for peer ${peerId}`);
}

// ─────────────────────────────────────────────
// AES-GCM
// ─────────────────────────────────────────────
async function encrypt(text, peerId) {
  const { encryptKey } = peerKeys.get(peerId);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const cipherText = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encryptKey,
    new TextEncoder().encode(text)
  );

  return { cipherText: new Uint8Array(cipherText), iv };
}

async function decrypt(cipherTextArr, ivArr, peerId) {
  const { decryptKey } = peerKeys.get(peerId);

  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(ivArr) },
    decryptKey,
    new Uint8Array(cipherTextArr)
  );

  return new TextDecoder().decode(plain);
}

// ─────────────────────────────────────────────
// RELAY
// ─────────────────────────────────────────────
function relay(payload, toPeerId) {
  ws.send(JSON.stringify({ ...payload, to: toPeerId }));
}

// ─────────────────────────────────────────────
// WEBSOCKET EVENTS
// ─────────────────────────────────────────────
ws.onopen = () => {
  setStatus('🔐 Waiting for a peer...');
};

ws.onmessage = async (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'welcome') {
    myId = data.clientId;
    console.log('[me] My ID:', myId);
    return;
  }

  if (data.type === 'peer_joined') {
    const peerId = data.peerId;
    setStatus('🤝 Peer connected — key exchange...');

    if (amInitiator(peerId)) {
      relay({ type: 'kyber_hello' }, peerId);
    }

    return;
  }

  if (data.type === 'peer_left') {
    peerKeys.delete(data.peerId);
    setStatus('⚠️ Peer disconnected');
    document.getElementById('sendBtn').disabled = true;
    return;
  }

  if (data.type === 'kyber_hello') {
    const peerId = data.from;

    const { rawSecret, sharedSecret } = await generateSharedSecret();
    await storePeerSecret(peerId, sharedSecret);

    relay({ type: 'kyber_ct', rawSecret: Array.from(rawSecret) }, peerId);

    enableChat();
    return;
  }

  if (data.type === 'kyber_ct') {
    const peerId = data.from;

    const sharedSecret = await deriveSharedSecret(data.rawSecret);
    await storePeerSecret(peerId, sharedSecret);

    enableChat();
    return;
  }

  if (data.type === 'chat') {
    const peerId = data.from;

    if (!peerKeys.has(peerId)) {
      appendMessage('[Message before key exchange]', 'received');
      return;
    }

    try {
      const plain = await decrypt(data.cipherText, data.iv, peerId);
      appendMessage('Friend: ' + plain, 'received');
    } catch (e) {
      appendMessage('[Decryption failed]', 'received');
    }
  }
};

ws.onerror = () => setStatus('❌ Connection error');
ws.onclose = () => setStatus('⚠️ Disconnected');

// ─────────────────────────────────────────────
// SEND MESSAGE
// ─────────────────────────────────────────────
async function sendMessage() {
  const msgEl = document.getElementById('message');
  const text = msgEl.value.trim();
  if (!text) return;

  if (peerKeys.size === 0) {
    setStatus('⚠️ No secure connection yet');
    return;
  }

  for (const [peerId] of peerKeys) {
    const { cipherText, iv } = await encrypt(text, peerId);

    relay({
      type: 'chat',
      cipherText: Array.from(cipherText),
      iv: Array.from(iv)
    }, peerId);
  }

  appendMessage('You: ' + text, 'sent');
  msgEl.value = '';
}

// ─────────────────────────────────────────────
// UI HELPERS
// ─────────────────────────────────────────────
function appendMessage(text, type) {
  const chat = document.getElementById('chat');
  const div = document.createElement('div');

  div.className = 'message ' + type;
  div.textContent = text;

  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
}

function setStatus(msg) {
  document.getElementById('statusMsg').textContent = msg;
}

function enableChat() {
  setStatus('🔒 Encrypted chat ready');
  document.getElementById('sendBtn').disabled = false;
}