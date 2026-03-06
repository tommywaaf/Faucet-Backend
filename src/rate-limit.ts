import type { Context, MiddlewareHandler } from "hono";
import type { Env } from "./index";

const KV_PREFIX = "rate:";
const TTL_SECONDS = 86400; // 24 hours

export function getClientIp(c: Context<Env>): string {
  return c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for") ?? "unknown";
}

export const rateLimitMiddleware: MiddlewareHandler<Env> = async (c, next) => {
  const ip = getClientIp(c);

  if (ip === "unknown") {
    return c.json({ error: "Unable to determine client IP" }, 400);
  }

  const existing = await c.env.RATE_LIMIT.get(`${KV_PREFIX}${ip}`);

  if (existing) {
    const claimedAt = new Date(existing);
    const expiresAt = new Date(claimedAt.getTime() + TTL_SECONDS * 1000);
    return c.json(
      {
        error: "Rate limit exceeded. You can only request tokens once every 24 hours.",
        retryAfter: expiresAt.toISOString(),
      },
      429,
    );
  }

  await next();
};

export async function recordSuccessfulRequest(kv: KVNamespace, ip: string): Promise<void> {
  await kv.put(`${KV_PREFIX}${ip}`, new Date().toISOString(), {
    expirationTtl: TTL_SECONDS,
  });
}
