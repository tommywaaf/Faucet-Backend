import { Hono } from "hono";
import { cors } from "hono/cors";
import { FAUCET_AMOUNTS } from "./config";
import { rateLimitMiddleware, recordSuccessfulRequest, getClientIp } from "./rate-limit";
import { sendFaucetTransaction } from "./fireblocks";

export type Env = {
  Bindings: {
    RATE_LIMIT: KVNamespace;
    ALLOWED_ORIGIN: string;
    FIREBLOCKS_API_KEY: string;
    FIREBLOCKS_SECRET_KEY: string;
    FIREBLOCKS_VAULT_ID: string;
  };
};

const app = new Hono<Env>();

app.use("/*", async (c, next) => {
  const origin = c.env.ALLOWED_ORIGIN;
  const handler = cors({
    origin,
    allowMethods: ["POST", "OPTIONS"],
    allowHeaders: ["Content-Type"],
    maxAge: 86400,
  });
  return handler(c, next);
});

app.use("/faucet", rateLimitMiddleware);

app.post("/faucet", async (c) => {
  const origin = c.req.header("origin");
  if (origin !== c.env.ALLOWED_ORIGIN) {
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

  if (!address || typeof address !== "string" || address.trim().length === 0) {
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
    const tx = await sendFaucetTransaction(c.env, assetId, address.trim(), amount);

    const ip = getClientIp(c);
    await recordSuccessfulRequest(c.env.RATE_LIMIT, ip);

    return c.json({
      success: true,
      transactionId: tx.id,
      status: tx.status,
      assetId,
      amount,
    });
  } catch (err) {
    console.error("Fireblocks transaction failed:", err);
    return c.json({ error: "Transaction failed. Please try again later." }, 500);
  }
});

app.get("/health", (c) => c.json({ status: "ok" }));

export default app;
