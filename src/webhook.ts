import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { Env } from "./types";

const TTL_30_DAYS = 2592000;

interface SessionData {
  hookIds: string[];
  createdAt: string;
}

interface HookData {
  sessionId: string;
  createdAt: string;
  secret?: string;
}

interface WebhookEvent {
  id: string;
  timestamp: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  query: string;
  contentType: string;
  size: number;
}

function generateHookId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

const app = new Hono<Env>();

app.get("/wht/session", async (c) => {
  const sessionId = getCookie(c, "wht_session");

  if (sessionId) {
    const session = await c.env.WEBHOOK_KV.get<SessionData>(
      `session:${sessionId}`,
      "json",
    );
    if (session) {
      const hooks = (
        await Promise.all(
          session.hookIds.map(async (hookId) => {
            const hook = await c.env.WEBHOOK_KV.get<HookData>(
              `hook:${hookId}`,
              "json",
            );
            if (!hook) return null;
            const events =
              (await c.env.WEBHOOK_KV.get<WebhookEvent[]>(
                `events:${hookId}`,
                "json",
              )) || [];
            return {
              id: hookId,
              createdAt: hook.createdAt,
              eventCount: events.length,
              ...(hook.secret ? { secret: hook.secret } : {}),
            };
          }),
        )
      ).filter(Boolean);

      return c.json({ sessionId, hookIds: session.hookIds, hooks });
    }
  }

  const newId = crypto.randomUUID();
  await c.env.WEBHOOK_KV.put(
    `session:${newId}`,
    JSON.stringify({ hookIds: [], createdAt: new Date().toISOString() }),
    { expirationTtl: TTL_30_DAYS },
  );

  setCookie(c, "wht_session", newId, {
    path: "/",
    httpOnly: true,
    sameSite: "None",
    secure: true,
    maxAge: TTL_30_DAYS,
  });

  return c.json({ sessionId: newId, hookIds: [], hooks: [] });
});

app.post("/wht/generate", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const session = await c.env.WEBHOOK_KV.get<SessionData>(
    `session:${sessionId}`,
    "json",
  );
  if (!session) return c.json({ error: "Session expired" }, 401);

  let secret: string | undefined;
  try {
    const body = await c.req.json<{ secret?: string }>();
    if (body.secret && typeof body.secret === "string") {
      secret = body.secret;
    }
  } catch {}

  const hookId = generateHookId();
  const now = new Date().toISOString();
  const hookValue: HookData = { sessionId, createdAt: now };
  if (secret) hookValue.secret = secret;

  await Promise.all([
    c.env.WEBHOOK_KV.put(
      `hook:${hookId}`,
      JSON.stringify(hookValue),
      { expirationTtl: TTL_30_DAYS },
    ),
    c.env.WEBHOOK_KV.put(`events:${hookId}`, JSON.stringify([]), {
      expirationTtl: TTL_30_DAYS,
    }),
  ]);

  session.hookIds.push(hookId);
  await c.env.WEBHOOK_KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: TTL_30_DAYS },
  );

  const origin = new URL(c.req.url).origin;
  return c.json({ hookId, url: `${origin}/hook/${hookId}` });
});

app.delete("/wht/url/:hookId", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const hookId = c.req.param("hookId");
  const hook = await c.env.WEBHOOK_KV.get<HookData>(
    `hook:${hookId}`,
    "json",
  );
  if (!hook || hook.sessionId !== sessionId) {
    return c.json({ error: "Not found" }, 404);
  }

  await Promise.all([
    c.env.WEBHOOK_KV.delete(`hook:${hookId}`),
    c.env.WEBHOOK_KV.delete(`events:${hookId}`),
  ]);

  const session = await c.env.WEBHOOK_KV.get<SessionData>(
    `session:${sessionId}`,
    "json",
  );
  if (session) {
    session.hookIds = session.hookIds.filter((id) => id !== hookId);
    await c.env.WEBHOOK_KV.put(
      `session:${sessionId}`,
      JSON.stringify(session),
      { expirationTtl: TTL_30_DAYS },
    );
  }

  try {
    const doId = c.env.WEBHOOK_LISTENER.idFromName(hookId);
    const stub = c.env.WEBHOOK_LISTENER.get(doId);
    await stub.fetch("https://do/notify", {
      method: "POST",
      body: JSON.stringify({ type: "deleted" }),
    });
  } catch {}

  return c.json({ ok: true });
});

app.delete("/wht/events/:hookId", async (c) => {
  const sessionId = getCookie(c, "wht_session");
  if (!sessionId) return c.json({ error: "No valid session" }, 401);

  const hookId = c.req.param("hookId");
  const hook = await c.env.WEBHOOK_KV.get<HookData>(
    `hook:${hookId}`,
    "json",
  );
  if (!hook || hook.sessionId !== sessionId) {
    return c.json({ error: "Not found" }, 404);
  }

  await c.env.WEBHOOK_KV.put(`events:${hookId}`, JSON.stringify([]), {
    expirationTtl: TTL_30_DAYS,
  });

  try {
    const doId = c.env.WEBHOOK_LISTENER.idFromName(hookId);
    const stub = c.env.WEBHOOK_LISTENER.get(doId);
    await stub.fetch("https://do/notify", {
      method: "POST",
      body: JSON.stringify({ type: "cleared" }),
    });
  } catch {}

  return c.json({ ok: true });
});

app.get("/wht/ws/:hookId", async (c) => {
  if (c.req.header("Upgrade") !== "websocket") {
    return c.text("Expected WebSocket upgrade", 426);
  }

  const hookId = c.req.param("hookId");
  const doId = c.env.WEBHOOK_LISTENER.idFromName(hookId);
  const stub = c.env.WEBHOOK_LISTENER.get(doId);

  return stub.fetch(c.req.raw);
});

app.all("/hook/:hookId", async (c) => {
  const hookId = c.req.param("hookId");
  const hook = await c.env.WEBHOOK_KV.get<HookData>(
    `hook:${hookId}`,
    "json",
  );
  if (!hook) return c.json({ error: "Hook not found" }, 404);

  const eventId = "evt_" + crypto.randomUUID().slice(0, 8);
  const event: WebhookEvent = {
    id: eventId,
    timestamp: new Date().toISOString(),
    method: c.req.method,
    headers: Object.fromEntries(c.req.raw.headers),
    body: await c.req.text(),
    query: new URL(c.req.url).search,
    contentType: c.req.header("content-type") || "",
    size: parseInt(c.req.header("content-length") || "0"),
  };

  const events =
    (await c.env.WEBHOOK_KV.get<WebhookEvent[]>(
      `events:${hookId}`,
      "json",
    )) || [];
  events.unshift(event);
  await c.env.WEBHOOK_KV.put(
    `events:${hookId}`,
    JSON.stringify(events.slice(0, 30)),
    { expirationTtl: TTL_30_DAYS },
  );

  try {
    const doId = c.env.WEBHOOK_LISTENER.idFromName(hookId);
    const stub = c.env.WEBHOOK_LISTENER.get(doId);
    await stub.fetch("https://do/broadcast", {
      method: "POST",
      body: JSON.stringify({ type: "event", event }),
    });
  } catch {}

  return c.json({ ok: true, id: eventId });
});

export default app;
