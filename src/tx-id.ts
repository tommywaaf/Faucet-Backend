import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { Env, TxIdSessionData } from "./types";
import { generateKeyPair, generateSignedTxId } from "./crypto-utils";

const SESSION_TTL = 31536000; // 1 year — sliding window, refreshed on every session access
const MAX_BATCH = 100;

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
      // Sliding window: refresh both the KV TTL and the cookie on every access
      await c.env.WEBHOOK_KV.put(
        `txid-session:${sessionId}`,
        JSON.stringify(existing),
        { expirationTtl: SESSION_TTL },
      );
      setCookie(c, "wht_session", sessionId, {
        path: "/",
        httpOnly: true,
        sameSite: "None",
        secure: true,
        maxAge: SESSION_TTL,
      });
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
    { expirationTtl: SESSION_TTL },
  );

  setCookie(c, "wht_session", sessionId, {
    path: "/",
    httpOnly: true,
    sameSite: "None",
    secure: true,
    maxAge: SESSION_TTL,
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

  const externalTxId = await generateSignedTxId(session.privateKeyHex);
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
    Array.from({ length: count }, () => generateSignedTxId(session.privateKeyHex)),
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
    { expirationTtl: SESSION_TTL },
  );

  return c.json({ publicKey: publicKeyHex });
});

export default app;
