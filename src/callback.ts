import { Hono } from "hono";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { Env, SessionData } from "./types";
import { verifySignedTxId } from "./crypto-utils";
import {
  generateRSAKeyPair,
  importPublicKey,
  jwtDecode,
  jwtVerify,
  jwtSign,
} from "./jwt";

const SESSION_TTL = 31536000; // 1 year — sliding window, refreshed on every session access

interface PolicyConditions {
  operations?: string[];
  assets?: string[];
  amountMin?: number | null;
  amountMax?: number | null;
  amountUsdMin?: number | null;
  amountUsdMax?: number | null;
  sourceIds?: string[];
  destIds?: string[];
  destAddressTypes?: string[];
  destAddresses?: string[];
  externalTxIdPublicKey?: string | null;
}

interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  conditions: PolicyConditions;
  action: "APPROVE" | "REJECT";
}

type SignAction = "APPROVE" | "REJECT";
type ApprovalAction = "APPROVE" | "REJECT" | "IGNORE";

type RequestType =
  | "tx_sign"
  | "tx_approval"
  | "config_change_sign"
  | "config_change_approval";

interface HandlerData {
  sessionId: string;
  cosignerPublicKey: string;
  callbackPrivateKey: string;
  callbackPublicKey: string;
  /** Default action for signing requests (tx_sign, config_change_sign). */
  action: SignAction;
  /**
   * Default action for approval requests (tx_approval, config_change_approval).
   * IGNORE dismisses the request without denying it (other quorum approvers
   * may still act independently). Per Fireblocks docs, IGNORE is only valid
   * for approval requests, not signing.
   */
  approvalAction: ApprovalAction;
  rules: PolicyRule[];
  createdAt: string;
}

interface CallbackEvent {
  id: string;
  timestamp: number;
  /** Which Co-Signer endpoint triggered this event. */
  requestType: RequestType;
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


async function evaluateRules(
  rules: PolicyRule[],
  tx: Record<string, unknown>,
): Promise<"APPROVE" | "REJECT" | null> {
  const destinations = tx.destinations as
    | Array<Record<string, unknown>>
    | undefined;
  const usdAmount =
    destinations?.[0]?.amountUSD != null
      ? Number(destinations[0].amountUSD)
      : null;

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const c = rule.conditions || {};
    if (c.operations?.length && !c.operations.includes(tx.operation as string))
      continue;
    if (c.assets?.length && !c.assets.includes(tx.asset as string)) continue;
    if (
      c.amountMin != null &&
      (tx.amount == null || Number(tx.amount) < c.amountMin)
    )
      continue;
    if (
      c.amountMax != null &&
      (tx.amount == null || Number(tx.amount) > c.amountMax)
    )
      continue;
    if (
      c.amountUsdMin != null &&
      (usdAmount == null || usdAmount < c.amountUsdMin)
    )
      continue;
    if (
      c.amountUsdMax != null &&
      (usdAmount == null || usdAmount > c.amountUsdMax)
    )
      continue;
    if (
      c.sourceIds?.length &&
      !c.sourceIds.includes(String(tx.sourceId))
    )
      continue;
    if (c.destIds?.length && !c.destIds.includes(String(tx.destId))) continue;
    if (
      c.destAddressTypes?.length &&
      !c.destAddressTypes.includes(tx.destAddressType as string)
    )
      continue;
    if (
      c.destAddresses?.length &&
      !c.destAddresses.some(
        (a) =>
          a.toLowerCase() ===
          ((tx.destAddress as string) || "").toLowerCase(),
      )
    )
      continue;
    if (c.externalTxIdPublicKey) {
      const extId = tx.externalTxId as string | undefined;
      if (!extId) continue;
      const valid = await verifySignedTxId(extId, c.externalTxIdPublicKey);
      if (!valid) continue;
    }
    return rule.action;
  }
  return null;
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
              approvalAction: h.approvalAction ?? "REJECT",
              rules: h.rules ?? [],
              createdAt: h.createdAt,
            };
          }),
        )
      ).filter(Boolean);

      // Sliding window: refresh both the KV TTL and the cookie on every access
      await c.env.WEBHOOK_KV.put(
        `session:${sessionId}`,
        JSON.stringify(session),
        { expirationTtl: SESSION_TTL },
      );
      setCookie(c, "wht_session", sessionId, {
        path: "/",
        httpOnly: true,
        sameSite: "None",
        secure: true,
        maxAge: SESSION_TTL,
      });

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
    { expirationTtl: SESSION_TTL },
  );

  setCookie(c, "wht_session", newId, {
    path: "/",
    httpOnly: true,
    sameSite: "None",
    secure: true,
    maxAge: SESSION_TTL,
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
    approvalAction: "REJECT",
    rules: [],
    createdAt: now,
  };

  await Promise.all([
    c.env.WEBHOOK_KV.put(
      `handler:${handlerId}`,
      JSON.stringify(handlerData),
      { expirationTtl: SESSION_TTL },
    ),
    c.env.WEBHOOK_KV.put(
      `handler_events:${handlerId}`,
      JSON.stringify([]),
      { expirationTtl: SESSION_TTL },
    ),
  ]);

  if (!session.handlerIds) session.handlerIds = [];
  session.handlerIds.push(handlerId);
  await c.env.WEBHOOK_KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: SESSION_TTL },
  );

  const origin = new URL(c.req.url).origin;
  return c.json({
    handlerId,
    callbackUrl: `${origin}/callback/${handlerId}`,
    callbackPublicKey: publicKey,
    action: "REJECT" as SignAction,
    approvalAction: "REJECT" as ApprovalAction,
    rules: [] as PolicyRule[],
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

  let body: { action?: string; approvalAction?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (body.action == null && body.approvalAction == null) {
    return c.json(
      { error: "Provide at least one of: action, approvalAction" },
      400,
    );
  }

  if (body.action != null) {
    if (body.action !== "APPROVE" && body.action !== "REJECT") {
      return c.json(
        { error: "action must be APPROVE or REJECT (IGNORE is not valid for signing requests)" },
        400,
      );
    }
    handler.action = body.action;
  }

  if (body.approvalAction != null) {
    if (
      body.approvalAction !== "APPROVE" &&
      body.approvalAction !== "REJECT" &&
      body.approvalAction !== "IGNORE"
    ) {
      return c.json(
        { error: "approvalAction must be APPROVE, REJECT, or IGNORE" },
        400,
      );
    }
    handler.approvalAction = body.approvalAction;
  }

  await c.env.WEBHOOK_KV.put(
    `handler:${handlerId}`,
    JSON.stringify(handler),
    { expirationTtl: SESSION_TTL },
  );

  return c.json({
    action: handler.action,
    approvalAction: handler.approvalAction,
  });
});

// -------------------------------------------------------------------------
// PUT /cbt/rules/:handlerId — replace rules array
// -------------------------------------------------------------------------

app.put("/cbt/rules/:handlerId", async (c) => {
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

  let body: { rules?: unknown };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (!Array.isArray(body.rules)) {
    return c.json({ error: "rules must be an array" }, 400);
  }

  handler.rules = body.rules as PolicyRule[];
  await c.env.WEBHOOK_KV.put(
    `handler:${handlerId}`,
    JSON.stringify(handler),
    { expirationTtl: SESSION_TTL },
  );

  return c.json({ ok: true });
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
      { expirationTtl: SESSION_TTL },
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
// Shared callback handler — used by all four Co-Signer endpoints
// -------------------------------------------------------------------------
//
// Per Fireblocks Co-Signer Callback Handler docs, the Co-Signer POSTs to:
//   /v2/tx_sign_request                 — transaction signing
//   /v2/tx_approval_request             — transaction approval (HA mode)
//   /v2/config_change_sign_request      — config change signing
//   /v2/config_change_approval_request  — config change approval
//
// For each, we must respond within 30s with a signed JWT containing
// { action, requestId, rejectionReason? }. IGNORE is only valid for
// approval requests.

async function handleCallback(
  c: Context<Env>,
  requestType: RequestType,
): Promise<Response> {
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

  // Decide the action.
  // Rules only apply to tx_sign (per current product scope).
  // Everything else uses the appropriate default (signing vs approval).
  let action: SignAction | ApprovalAction;
  if (requestType === "tx_sign") {
    action = (await evaluateRules(handler.rules ?? [], decoded)) ?? handler.action;
  } else if (requestType === "config_change_sign") {
    action = handler.action;
  } else {
    // tx_approval or config_change_approval
    action = handler.approvalAction ?? "REJECT";
  }

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

  try {
    await jwtVerify(signedResponse, handler.callbackPublicKey);
  } catch (e) {
    console.error(
      `[SELF-VERIFY FAIL] handler=${handlerId} — key pair mismatch in KV!`,
      e,
    );
    return c.text("Internal signing error", 500);
  }

  console.log(
    `[CALLBACK] handler=${handlerId} type=${requestType} action=${action}`,
  );

  const event: CallbackEvent = {
    id: "evt_" + crypto.randomUUID().slice(0, 8),
    timestamp: Date.now(),
    requestType,
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
    { expirationTtl: SESSION_TTL },
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
}

// -------------------------------------------------------------------------
// Co-Signer endpoints
// -------------------------------------------------------------------------

app.post("/callback/:handlerId/v2/tx_sign_request", (c) =>
  handleCallback(c, "tx_sign"),
);

app.post("/callback/:handlerId/v2/tx_approval_request", (c) =>
  handleCallback(c, "tx_approval"),
);

app.post("/callback/:handlerId/v2/config_change_sign_request", (c) =>
  handleCallback(c, "config_change_sign"),
);

app.post("/callback/:handlerId/v2/config_change_approval_request", (c) =>
  handleCallback(c, "config_change_approval"),
);

export default app;
