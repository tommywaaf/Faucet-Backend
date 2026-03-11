import { Hono } from "hono";
import { cors } from "hono/cors";
import type { MiddlewareHandler } from "hono";
import { FAUCET_AMOUNTS } from "./config";
import {
  rateLimitMiddleware,
  recordSuccessfulRequest,
  getClientIp,
} from "./rate-limit";
import { sendFaucetTransaction } from "./fireblocks";
import webhookApp from "./webhook";
import callbackApp from "./callback";

export type { Env } from "./types";
export { WebhookListener } from "./webhook-listener";

import type { Env } from "./types";

const app = new Hono<Env>();

const faucetCors: MiddlewareHandler<Env> = async (c, next) => {
  const allowedOrigins = c.env.ALLOWED_ORIGINS.split(",");
  return cors({
    origin: (o) => (allowedOrigins.includes(o) ? o : ""),
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type"],
    maxAge: 86400,
  })(c, next);
};
app.use("/faucet", faucetCors);
app.use("/health", faucetCors);

// CORS for /wht/* (credentials-based, specific origin)
app.use("/wht/*", async (c, next) => {
  const allowedOrigins = c.env.ALLOWED_ORIGINS.split(",");
  return cors({
    origin: (o) => (allowedOrigins.includes(o) ? o : ""),
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type"],
    credentials: true,
    maxAge: 86400,
  })(c, next);
});

// CORS for /cbt/* (credentials-based, same as /wht/*)
app.use("/cbt/*", async (c, next) => {
  const allowedOrigins = c.env.ALLOWED_ORIGINS.split(",");
  return cors({
    origin: (o) => (allowedOrigins.includes(o) ? o : ""),
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type"],
    credentials: true,
    maxAge: 86400,
  })(c, next);
});

// CORS for /hook/* (open — external services call these)
app.use(
  "/hook/*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["*"],
    maxAge: 86400,
  }),
);

app.use("/faucet", rateLimitMiddleware);

// Webhook testing routes
app.route("/", webhookApp);

// Callback handler testing routes
app.route("/", callbackApp);

app.post("/faucet", async (c) => {
  const origin = c.req.header("origin");
  const allowedOrigins = c.env.ALLOWED_ORIGINS.split(",");
  if (!origin || !allowedOrigins.includes(origin)) {
    return c.json({ error: "Forbidden" }, 403);
  }

  let body: { assetId?: string; address?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const { assetId, address } = body;

  if (!assetId || typeof assetId !== "string") {
    return c.json({ error: "Missing or invalid assetId" }, 400);
  }

  if (
    !address ||
    typeof address !== "string" ||
    address.trim().length === 0
  ) {
    return c.json({ error: "Missing or invalid address" }, 400);
  }

  const amount = FAUCET_AMOUNTS[assetId];
  if (!amount) {
    return c.json(
      {
        error: `Unsupported asset: ${assetId}`,
        supportedAssets: Object.keys(FAUCET_AMOUNTS),
      },
      400,
    );
  }

  try {
    const tx = await sendFaucetTransaction(
      c.env,
      assetId,
      address.trim(),
      amount,
    );

    const ip = getClientIp(c);
    await recordSuccessfulRequest(c.env.RATE_LIMIT, ip, assetId);

    return c.json({
      success: true,
      transactionId: tx.id,
      status: tx.status,
      assetId,
      amount,
    });
  } catch (err) {
    console.error("Fireblocks transaction failed:", err);
    return c.json(
      { error: "Transaction failed. Please try again later." },
      500,
    );
  }
});

app.get("/health", (c) => c.json({ status: "ok" }));

export default app;
