import { Hono } from "hono";
import type { Env } from "./types";

const TTL_30_DAYS = 2592000;

interface CosignerRequest {
  id: string;
  pairingToken: string;
  callbackUrl?: string;
  callbackPublicKey?: string;
  status: "pending" | "picked_up" | "completed" | "failed";
  submittedAt: string;
  pickedUpAt?: string;
  completedAt?: string;
  error?: string;
}

function generateCosignerId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

function requireBearerAuth(c: { req: { header: (name: string) => string | undefined }; env: { COSIGNER_API_KEY: string } }): boolean {
  const auth = c.req.header("Authorization");
  if (!auth) return false;
  const [scheme, token] = auth.split(" ");
  return scheme === "Bearer" && token === c.env.COSIGNER_API_KEY;
}

const app = new Hono<Env>();

// POST /cosigner/submit — frontend submits a pairing token for cosigner setup
app.post("/cosigner/submit", async (c) => {
  let body: { pairingToken?: string; callbackUrl?: string; callbackPublicKey?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const { pairingToken, callbackUrl, callbackPublicKey } = body;
  if (!pairingToken || typeof pairingToken !== "string") {
    return c.json({ error: "Missing or invalid pairingToken" }, 400);
  }

  const id = generateCosignerId();
  const now = new Date().toISOString();

  const record: CosignerRequest = {
    id,
    pairingToken,
    callbackUrl,
    callbackPublicKey,
    status: "pending",
    submittedAt: now,
  };

  const queue: string[] =
    (await c.env.WEBHOOK_KV.get<string[]>("cosigner:queue", "json")) ?? [];
  queue.push(id);

  await Promise.all([
    c.env.WEBHOOK_KV.put(`cosigner:${id}`, JSON.stringify(record), {
      expirationTtl: TTL_30_DAYS,
    }),
    c.env.WEBHOOK_KV.put("cosigner:queue", JSON.stringify(queue), {
      expirationTtl: TTL_30_DAYS,
    }),
  ]);

  return c.json({ id, status: "pending" });
});

// GET /cosigner/pending — cosigner agent polls for the next pending request
app.get("/cosigner/pending", async (c) => {
  if (!requireBearerAuth(c)) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const queue: string[] =
    (await c.env.WEBHOOK_KV.get<string[]>("cosigner:queue", "json")) ?? [];

  if (queue.length === 0) {
    return c.body(null, 204);
  }

  const nextId = queue.shift()!;
  const record = await c.env.WEBHOOK_KV.get<CosignerRequest>(
    `cosigner:${nextId}`,
    "json",
  );

  if (!record) {
    await c.env.WEBHOOK_KV.put("cosigner:queue", JSON.stringify(queue), {
      expirationTtl: TTL_30_DAYS,
    });
    return c.body(null, 204);
  }

  record.status = "picked_up";
  record.pickedUpAt = new Date().toISOString();

  await Promise.all([
    c.env.WEBHOOK_KV.put(`cosigner:${nextId}`, JSON.stringify(record), {
      expirationTtl: TTL_30_DAYS,
    }),
    c.env.WEBHOOK_KV.put("cosigner:queue", JSON.stringify(queue), {
      expirationTtl: TTL_30_DAYS,
    }),
  ]);

  return c.json({
    id: record.id,
    pairingToken: record.pairingToken,
    callbackUrl: record.callbackUrl,
    callbackPublicKey: record.callbackPublicKey,
  });
});

// PUT /cosigner/complete/:id — cosigner agent reports result
app.put("/cosigner/complete/:id", async (c) => {
  if (!requireBearerAuth(c)) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const id = c.req.param("id");
  const record = await c.env.WEBHOOK_KV.get<CosignerRequest>(
    `cosigner:${id}`,
    "json",
  );
  if (!record) {
    return c.json({ error: "Not found" }, 404);
  }

  let body: { success?: boolean; error?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (typeof body.success !== "boolean") {
    return c.json({ error: "Missing or invalid 'success' field" }, 400);
  }

  record.status = body.success ? "completed" : "failed";
  record.completedAt = new Date().toISOString();
  if (body.error) record.error = body.error;

  await c.env.WEBHOOK_KV.put(`cosigner:${id}`, JSON.stringify(record), {
    expirationTtl: TTL_30_DAYS,
  });

  return c.json({ ok: true });
});

// GET /cosigner/status/:id — frontend polls for request status
app.get("/cosigner/status/:id", async (c) => {
  const id = c.req.param("id");
  const record = await c.env.WEBHOOK_KV.get<CosignerRequest>(
    `cosigner:${id}`,
    "json",
  );
  if (!record) {
    return c.json({ error: "Not found" }, 404);
  }

  return c.json({
    id: record.id,
    status: record.status,
    submittedAt: record.submittedAt,
    pickedUpAt: record.pickedUpAt,
    completedAt: record.completedAt,
    error: record.error,
  });
});

export default app;
