import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { Env, SessionData } from "./types";
import {
  generateRSAKeyPair,
  importPublicKey,
  jwtDecode,
  jwtVerify,
  jwtSign,
} from "./jwt";

const TTL_30_DAYS = 2592000;

interface HandlerData {
  sessionId: string;
  cosignerPublicKey: string;
  callbackPrivateKey: string;
  callbackPublicKey: string;
  action: "APPROVE" | "REJECT";
  createdAt: string;
}

interface CallbackEvent {
  id: string;
  timestamp: number;
  requestId: string;
  operation: string;
  asset: string;
  amount: string;
  sourceType: string;
  sourceId: string;
  destType: string;
  destId: string;
  destAddress: string;
  action: string;
  verified: boolean;
  rawPayload: Record<string, unknown>;
  /** Raw request body received from cosigner (JWT string). */
  rawRequestReceived: string;
  /** Raw response body sent back to cosigner (signed JWT string). */
  rawResponseSent: string;
}

function generateHandlerId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

const app = new Hono<Env>();

// -------------------------------------------------------------------------
// GET /cbt/session — initialise or resume session, return handlers
// -------------------------------------------------------------------------

app.get("/cbt/session", async (c) => {
  const sessionId = getCookie(c, "wht_session");

  if (sessionId) {
    const session = await c.env.WEBHOOK_KV.get<SessionData>(
      `session:${sessionId}`,
      "json",
    );
    if (session) {
      const handlerIds = session.handlerIds ?? [];
      const handlers = (
        await Promise.all(
          handlerIds.map(async (id) => {
            const h = await c.env.WEBHOOK_KV.get<HandlerData>(
              `handler:${id}`,
              "json",
            );
            if (!h) return null;
            return {
              id,
              callbackUrl: `${new URL(c.req.url).origin}/callback/${id}`,
              callbackPublicKey: h.callbackPublicKey,
              action: h.action,
              createdAt: h.createdAt,
            };
          }),
        )
      ).filter(Boolean);

      return c.json({ handlers });
    }
  }

  const newId = crypto.randomUUID();
  await c.env.WEBHOOK_KV.put(
    `session:${newId}`,
    JSON.stringify({
      hookIds: [],
      handlerIds: [],
      createdAt: new Date().toISOString(),
    }),
    { expirationTtl: TTL_30_DAYS },
  );

  setCookie(c, "wht_session", newId, {
    path: "/",
    httpOnly: true,
    sameSite: "None",
    secure: true,
    maxAge: TTL_30_DAYS,
  });

  return c.json({ handlers: [] });
});

// -------------------------------------------------------------------------
// POST /cbt/create — generate RSA key pair, store handler
// -------------------------------------------------------------------------

app.post("/cbt/create", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const session = await c.env.WEBHOOK_KV.get<SessionData>(
    `session:${sessionId}`,
    "json",
  );
  if (!session) return c.json({ error: "Session expired" }, 401);

  let body: { cosignerPublicKey?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const { cosignerPublicKey } = body;
  if (!cosignerPublicKey || typeof cosignerPublicKey !== "string") {
    return c.json({ error: "Missing cosignerPublicKey" }, 400);
  }

  try {
    await importPublicKey(cosignerPublicKey);
  } catch {
    return c.json({ error: "Invalid PEM format for cosignerPublicKey" }, 400);
  }

  const { publicKey, privateKey } = await generateRSAKeyPair();
  const handlerId = generateHandlerId();
  const now = new Date().toISOString();

  const handlerData: HandlerData = {
    sessionId,
    cosignerPublicKey,
    callbackPrivateKey: privateKey,
    callbackPublicKey: publicKey,
    action: "REJECT",
    createdAt: now,
  };

  await Promise.all([
    c.env.WEBHOOK_KV.put(
      `handler:${handlerId}`,
      JSON.stringify(handlerData),
      { expirationTtl: TTL_30_DAYS },
    ),
    c.env.WEBHOOK_KV.put(
      `handler_events:${handlerId}`,
      JSON.stringify([]),
      { expirationTtl: TTL_30_DAYS },
    ),
  ]);

  if (!session.handlerIds) session.handlerIds = [];
  session.handlerIds.push(handlerId);
  await c.env.WEBHOOK_KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: TTL_30_DAYS },
  );

  const origin = new URL(c.req.url).origin;
  return c.json({
    handlerId,
    callbackUrl: `${origin}/callback/${handlerId}`,
    callbackPublicKey: publicKey,
    action: "REJECT" as const,
  });
});

// -------------------------------------------------------------------------
// PUT /cbt/action/:handlerId — toggle APPROVE / REJECT
// -------------------------------------------------------------------------

app.put("/cbt/action/:handlerId", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const handlerId = c.req.param("handlerId");
  const handler = await c.env.WEBHOOK_KV.get<HandlerData>(
    `handler:${handlerId}`,
    "json",
  );
  if (!handler || handler.sessionId !== sessionId) {
    return c.json({ error: "Not found" }, 404);
  }

  let body: { action?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (body.action !== "APPROVE" && body.action !== "REJECT") {
    return c.json({ error: "Action must be APPROVE or REJECT" }, 400);
  }

  handler.action = body.action;
  await c.env.WEBHOOK_KV.put(
    `handler:${handlerId}`,
    JSON.stringify(handler),
    { expirationTtl: TTL_30_DAYS },
  );

  return c.json({ action: body.action });
});

// -------------------------------------------------------------------------
// DELETE /cbt/:handlerId — tear down handler
// -------------------------------------------------------------------------

app.delete("/cbt/:handlerId", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const handlerId = c.req.param("handlerId");
  const handler = await c.env.WEBHOOK_KV.get<HandlerData>(
    `handler:${handlerId}`,
    "json",
  );
  if (!handler || handler.sessionId !== sessionId) {
    return c.json({ error: "Not found" }, 404);
  }

  await Promise.all([
    c.env.WEBHOOK_KV.delete(`handler:${handlerId}`),
    c.env.WEBHOOK_KV.delete(`handler_events:${handlerId}`),
  ]);

  const session = await c.env.WEBHOOK_KV.get<SessionData>(
    `session:${sessionId}`,
    "json",
  );
  if (session) {
    session.handlerIds = (session.handlerIds ?? []).filter(
      (id) => id !== handlerId,
    );
    await c.env.WEBHOOK_KV.put(
      `session:${sessionId}`,
      JSON.stringify(session),
      { expirationTtl: TTL_30_DAYS },
    );
  }

  try {
    const doId = c.env.WEBHOOK_LISTENER.idFromName(`cb_${handlerId}`);
    const stub = c.env.WEBHOOK_LISTENER.get(doId);
    await stub.fetch("https://do/notify", {
      method: "POST",
      body: JSON.stringify({ type: "deleted" }),
    });
  } catch {}

  return c.json({ deleted: true });
});

// -------------------------------------------------------------------------
// GET /cbt/ws/:handlerId — WebSocket upgrade (real-time event stream)
// -------------------------------------------------------------------------

app.get("/cbt/ws/:handlerId", async (c) => {
  if (c.req.header("Upgrade") !== "websocket") {
    return c.text("Expected WebSocket upgrade", 426);
  }

  const handlerId = c.req.param("handlerId");
  const doId = c.env.WEBHOOK_LISTENER.idFromName(`cb_${handlerId}`);
  const stub = c.env.WEBHOOK_LISTENER.get(doId);

  return stub.fetch(c.req.raw);
});

// -------------------------------------------------------------------------
// POST /callback/:handlerId/v2/tx_sign_request — Co-Signer endpoint
// -------------------------------------------------------------------------

app.post("/callback/:handlerId/v2/tx_sign_request", async (c) => {
  const handlerId = c.req.param("handlerId");
  const handler = await c.env.WEBHOOK_KV.get<HandlerData>(
    `handler:${handlerId}`,
    "json",
  );
  if (!handler) return c.text("Not found", 404);

  const rawBody = await c.req.text();

  let decoded: Record<string, unknown>;
  try {
    decoded = jwtDecode(rawBody);
  } catch {
    return c.text("Invalid JWT", 400);
  }

  try {
    await jwtVerify(rawBody, handler.cosignerPublicKey);
  } catch {
    return c.text("Unauthorized", 401);
  }

  const { requestId } = decoded;
  const action = handler.action;

  const responsePayload: Record<string, unknown> = {
    action,
    requestId,
  };
  if (action === "REJECT") {
    responsePayload.rejectionReason = "Callback handler auto-reject";
  }

  const signedResponse = await jwtSign(
    responsePayload,
    handler.callbackPrivateKey,
  );

  const event: CallbackEvent = {
    id: "evt_" + crypto.randomUUID().slice(0, 8),
    timestamp: Date.now(),
    requestId: String(decoded.requestId ?? ""),
    operation: String(decoded.operation ?? ""),
    asset: String(decoded.asset ?? ""),
    amount: String(
      (decoded.amountStr as string) ?? (decoded.amount as string) ?? "",
    ),
    sourceType: String(decoded.sourceType ?? ""),
    sourceId: String(decoded.sourceId ?? ""),
    destType: String(decoded.destType ?? ""),
    destId: String(decoded.destId ?? ""),
    destAddress: String(
      decoded.destAddress ??
        ((decoded.destinations as Array<Record<string, unknown>>)?.[0]
          ?.displayDstAddress as string) ??
        "",
    ),
    action,
    verified: true,
    rawPayload: decoded,
    rawRequestReceived: rawBody,
    rawResponseSent: signedResponse,
  };

  const events =
    (await c.env.WEBHOOK_KV.get<CallbackEvent[]>(
      `handler_events:${handlerId}`,
      "json",
    )) ?? [];
  events.unshift(event);
  await c.env.WEBHOOK_KV.put(
    `handler_events:${handlerId}`,
    JSON.stringify(events.slice(0, 30)),
    { expirationTtl: TTL_30_DAYS },
  );

  try {
    const doId = c.env.WEBHOOK_LISTENER.idFromName(`cb_${handlerId}`);
    const stub = c.env.WEBHOOK_LISTENER.get(doId);
    await stub.fetch("https://do/broadcast", {
      method: "POST",
      body: JSON.stringify({ type: "event", event }),
    });
  } catch {}

  return c.text(signedResponse);
});

export default app;
