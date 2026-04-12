export function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

export function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function fromBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// HMAC-SHA256: generateKey() is fully supported in Cloudflare Workers.
// 256-bit key, symmetric — verification runs server-side so the key never
// needs to leave the Worker for signing; the client only sees it when the
// user explicitly copies it to configure a policy rule.

export async function generateKeyPair(): Promise<{
  privateKeyHex: string;
  publicKeyHex: string;
}> {
  const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"],
  );
  const keyBuf = await crypto.subtle.exportKey("raw", key);
  const keyHex = toHex(keyBuf);
  // Symmetric — both "sides" use the same key
  return { privateKeyHex: keyHex, publicKeyHex: keyHex };
}

export async function generateSignedTxId(secretKeyHex: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(secretKeyHex),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const sigBuf = await crypto.subtle.sign("HMAC", key, idBytes);
  return `${toBase64Url(idBytes)}.${toBase64Url(sigBuf)}`;
}

export async function verifySignedTxId(
  externalTxId: string,
  secretKeyHex: string,
): Promise<boolean> {
  try {
    const parts = externalTxId.split(".");
    if (parts.length !== 2) return false;
    const idBytes = fromBase64Url(parts[0]);
    const sigBytes = fromBase64Url(parts[1]);
    const key = await crypto.subtle.importKey(
      "raw",
      fromHex(secretKeyHex),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify("HMAC", key, sigBytes, idBytes);
  } catch {
    return false;
  }
}
