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

export async function generateEd25519KeyPair(): Promise<{
  privateKeyHex: string;
  publicKeyHex: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const [privateKeyBuf, publicKeyBuf] = await Promise.all([
    crypto.subtle.exportKey("raw", keyPair.privateKey),
    crypto.subtle.exportKey("raw", keyPair.publicKey),
  ]);
  return {
    privateKeyHex: toHex(privateKeyBuf),
    publicKeyHex: toHex(publicKeyBuf),
  };
}

export async function generateSignedTxId(privateKeyHex: string): Promise<string> {
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const privateKey = await crypto.subtle.importKey(
    "raw",
    fromHex(privateKeyHex),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("Ed25519", privateKey, idBytes);
  return `${toBase64Url(idBytes)}.${toBase64Url(sigBuf)}`;
}
