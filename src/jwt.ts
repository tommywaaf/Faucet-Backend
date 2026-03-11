// ---------------------------------------------------------------------------
// Base64 / Base64url helpers
// ---------------------------------------------------------------------------

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

function base64urlEncode(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str: string): string {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad) b64 += "=".repeat(4 - pad);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function bufferToBase64url(buf: ArrayBuffer): string {
  return arrayBufferToBase64(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlToArrayBuffer(str: string): ArrayBuffer {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad) b64 += "=".repeat(4 - pad);
  return base64ToArrayBuffer(b64);
}

// ---------------------------------------------------------------------------
// PEM ↔ DER conversion
// ---------------------------------------------------------------------------

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/[\r\n\s]/g, "");
  return base64ToArrayBuffer(b64);
}

function derToPem(der: ArrayBuffer, label: string): string {
  const b64 = arrayBufferToBase64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

// ---------------------------------------------------------------------------
// Key import / export
// ---------------------------------------------------------------------------

const RSA_ALGO = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

export async function importPublicKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", pemToDer(pem), RSA_ALGO, false, [
    "verify",
  ]);
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pemToDer(pem), RSA_ALGO, false, [
    "sign",
  ]);
}

// ---------------------------------------------------------------------------
// RSA key-pair generation (RS256, 2048-bit)
// ---------------------------------------------------------------------------

export async function generateRSAKeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const [privDer, pubDer] = (await Promise.all([
    crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    crypto.subtle.exportKey("spki", keyPair.publicKey),
  ])) as [ArrayBuffer, ArrayBuffer];

  return {
    privateKey: derToPem(privDer, "PRIVATE KEY"),
    publicKey: derToPem(pubDer, "PUBLIC KEY"),
  };
}

// ---------------------------------------------------------------------------
// JWT decode / verify / sign  (RS256 only)
// ---------------------------------------------------------------------------

export function jwtDecode(token: string): Record<string, unknown> {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  return JSON.parse(base64urlDecode(parts[1]));
}

export async function jwtVerify(
  token: string,
  publicKeyPem: string,
): Promise<Record<string, unknown>> {
  const parts = token.trim().split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");

  const key = await importPublicKey(publicKeyPem);
  const data = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const sig = base64urlToArrayBuffer(parts[2]);

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  if (!valid) throw new Error("Invalid JWT signature");

  return JSON.parse(base64urlDecode(parts[1]));
}

export async function jwtSign(
  payload: Record<string, unknown>,
  privateKeyPem: string,
): Promise<string> {
  const header = base64urlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;

  const key = await importPrivateKey(privateKeyPem);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${bufferToBase64url(sig)}`;
}
