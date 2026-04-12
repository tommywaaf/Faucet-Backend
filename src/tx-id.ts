import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { Env, TxIdSessionData } from "./types";

const TTL_30_DAYS = 2592000;
const MAX_BATCH = 100;

// ── Helpers ──────────────────────────────────────────────────────────────────

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

function toBase64Url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateKeyPair(): Promise<{ privateKeyHex: string; publicKeyHex: string }> {
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

async function signUUID(privateKeyHex: string): Promise<string> {
  const privateKeyBytes = fromHex(privateKeyHex);
  const privateKey = await crypto.subtle.importKey(
    "raw",
    privateKeyBytes,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const sigBuf = await crypto.subtle.sign("Ed25519", privateKey, idBytes);
  return `${toBase64Url(idBytes)}.${toBase64Url(sigBuf)}`;
}

async function getOrCreateSession(
  kv: KVNamespace,
  sessionId: string,
): Promise<TxIdSessionData | null> {
  return kv.get<TxIdSessionData>(`txid-session:${sessionId}`, "json");
}

// ── App ───────────────────────────────────────────────────────────────────────

const app = new Hono<Env>();

// -------------------------------------------------------------------------
// GET /tx-id/session — create or resume a tx-id key pair session
// -------------------------------------------------------------------------

app.get("/tx-id/session", async (c) => {
  let sessionId = getCookie(c, "wht_session");

  if (sessionId) {
    const existing = await getOrCreateSession(c.env.WEBHOOK_KV, sessionId);
    if (existing) {
      return c.json({ publicKey: existing.publicKeyHex });
    }
  }

  if (!sessionId) {
    sessionId = crypto.randomUUID();
  }

  const { privateKeyHex, publicKeyHex } = await generateKeyPair();
  const data: TxIdSessionData = {
    privateKeyHex,
    publicKeyHex,
    createdAt: new Date().toISOString(),
  };

  await c.env.WEBHOOK_KV.put(
    `txid-session:${sessionId}`,
    JSON.stringify(data),
    { expirationTtl: TTL_30_DAYS },
  );

  setCookie(c, "wht_session", sessionId, {
    path: "/",
    httpOnly: true,
    sameSite: "None",
    secure: true,
    maxAge: TTL_30_DAYS,
  });

  return c.json({ publicKey: publicKeyHex });
});

// -------------------------------------------------------------------------
// GET /tx-id/generate — generate a single signed externalTxId
// -------------------------------------------------------------------------

app.get("/tx-id/generate", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No session" }, 401);

  const session = await getOrCreateSession(c.env.WEBHOOK_KV, sessionId);
  if (!session) return c.json({ error: "Session not found — visit /tx-id/session first" }, 404);

  const externalTxId = await signUUID(session.privateKeyHex);
  return c.json({ externalTxId });
});

// -------------------------------------------------------------------------
// POST /tx-id/generate — generate a batch of signed externalTxIds
// body: { count: number }
// -------------------------------------------------------------------------

app.post("/tx-id/generate", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No session" }, 401);

  const session = await getOrCreateSession(c.env.WEBHOOK_KV, sessionId);
  if (!session) return c.json({ error: "Session not found — visit /tx-id/session first" }, 404);

  let count = 1;
  try {
    const body = await c.req.json<{ count?: unknown }>();
    if (typeof body.count === "number" && body.count >= 1 && body.count <= MAX_BATCH) {
      count = Math.floor(body.count);
    }
  } catch {
    // use default count of 1
  }

  const externalTxIds = await Promise.all(
    Array.from({ length: count }, () => signUUID(session.privateKeyHex)),
  );

  return c.json({ externalTxIds });
});

// -------------------------------------------------------------------------
// DELETE /tx-id/session — regenerate the key pair for this session
// -------------------------------------------------------------------------

app.delete("/tx-id/session", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No session" }, 401);

  const { privateKeyHex, publicKeyHex } = await generateKeyPair();
  const data: TxIdSessionData = {
    privateKeyHex,
    publicKeyHex,
    createdAt: new Date().toISOString(),
  };

  await c.env.WEBHOOK_KV.put(
    `txid-session:${sessionId}`,
    JSON.stringify(data),
    { expirationTtl: TTL_30_DAYS },
  );

  return c.json({ publicKey: publicKeyHex });
});

export default app;
