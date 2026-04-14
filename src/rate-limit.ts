import type { Context, MiddlewareHandler } from "hono";
import type { Env } from "./types";

const KV_PREFIX = "rate:";
const TTL_SECONDS = 86400; // 24 hours
const MAX_REQUESTS = 20;

export function getClientIp(c: Context<Env>): string {
  return c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for") ?? "unknown";
}

export const rateLimitMiddleware: MiddlewareHandler<Env> = async (c, next) => {
  const ip = getClientIp(c);

  if (ip === "unknown") {
    return c.json({ error: "Unable to determine client IP" }, 400);
  }

  let assetId: string | undefined;
  try {
    const body = await c.req.json();
    assetId = body.assetId;
  } catch {
    return await next();
  }

  if (!assetId || typeof assetId !== "string") {
    return await next();
  }

  const key = `${KV_PREFIX}${ip}:${assetId}`;
  const existing = await c.env.RATE_LIMIT.get(key);
  const count = existing ? parseInt(existing, 10) : 0;

  if (count >= MAX_REQUESTS) {
    return c.json(
      {
        error: `Rate limit exceeded for ${assetId}. Maximum ${MAX_REQUESTS} requests per asset per 24 hours.`,
        retryAfter: new Date(Date.now() + TTL_SECONDS * 1000).toISOString(),
      },
      429,
    );
  }

  await next();
};

export async function recordSuccessfulRequest(kv: KVNamespace, ip: string, assetId: string): Promise<void> {
  const key = `${KV_PREFIX}${ip}:${assetId}`;
  const existing = await kv.get(key);
  const count = existing ? parseInt(existing, 10) : 0;
  await kv.put(key, String(count + 1), { expirationTtl: TTL_SECONDS });
}
