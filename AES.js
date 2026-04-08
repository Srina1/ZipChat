// AES key generation, export, and import
export async function generateAESKey() {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

export async function exportAESKey(aesKey) {
    const raw = await crypto.subtle.exportKey("raw", aesKey);
    return new Uint8Array(raw);
}

export async function importAESKey(raw) {
    return crypto.subtle.importKey(
        "raw",
        raw,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );
}