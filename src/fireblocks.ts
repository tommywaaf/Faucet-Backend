const FIREBLOCKS_API_BASE = "https://api.fireblocks.io";

export interface FireblocksEnv {
  FIREBLOCKS_API_KEY: string;
  FIREBLOCKS_SECRET_KEY: string;
  FIREBLOCKS_VAULT_ID: string;
}

export interface TransactionResult {
  id: string;
  status: string;
}

export async function sendFaucetTransaction(
  env: FireblocksEnv,
  assetId: string,
  destinationAddress: string,
  amount: string,
  externalTxId?: string,
): Promise<TransactionResult> {
  const path = "/v1/transactions";
  const bodyObj: Record<string, unknown> = {
    assetId,
    amount,
    source: {
      type: "VAULT_ACCOUNT",
      id: env.FIREBLOCKS_VAULT_ID,
    },
    destination: {
      type: "ONE_TIME_ADDRESS",
      oneTimeAddress: { address: destinationAddress },
    },
    note: `Faucet drip: ${amount} ${assetId}`,
  };
  if (externalTxId) bodyObj.externalTxId = externalTxId;
  const body = JSON.stringify(bodyObj);

  const token = await signJwt(env.FIREBLOCKS_API_KEY, env.FIREBLOCKS_SECRET_KEY, path, body);

  const res = await fetch(`${FIREBLOCKS_API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": env.FIREBLOCKS_API_KEY,
      Authorization: `Bearer ${token}`,
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Fireblocks API error ${res.status}: ${text}`);
  }

  const data: TransactionResult = await res.json();
  return data;
}

// --- JWT signing with Web Crypto (no external deps) ---

async function signJwt(
  apiKey: string,
  secretKeyPem: string,
  uri: string,
  body: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const bodyHash = await sha256Hex(body);

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    uri,
    nonce,
    iat: now,
    exp: now + 30,
    sub: apiKey,
    bodyHash,
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importPrivateKey(secretKeyPem);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${base64urlFromBuffer(signature)}`;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
  const pemBody = pem
    .replace(/-----BEGIN (RSA )?PRIVATE KEY-----/g, "")
    .replace(/-----END (RSA )?PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function sha256Hex(data: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64url(str: string): string {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlFromBuffer(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
