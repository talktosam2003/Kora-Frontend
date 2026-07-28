/**
 * Distributed rate limiter for the upload API.
 *
 * Production: uses Redis (ioredis) with a fixed-window counter per key.
 *   - Key format: `rl:{composite}` where composite is `{wallet}:{ip}` or
 *     just `ip:{ip}` for the IP-only check.
 *   - TTL is set equal to the window duration so keys expire automatically.
 *
 * Development / fallback: falls back to an in-memory Map when REDIS_URL is
 * not set or when the Redis connection fails, so local dev requires no Redis.
 *
 * Usage:
 *   const result = await checkRateLimit("wallet:ip", { windowMs, max });
 *   if (!result.allowed) return 429 with Retry-After header
 */

import { logger } from "@/lib/logger";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RateLimitOptions {
  /** Sliding-window length in milliseconds */
  windowMs: number;
  /** Maximum number of requests allowed in the window */
  max: number;
}

export interface RateLimitResult {
  allowed: boolean;
  /** Seconds until the client may retry (only present when allowed=false) */
  retryAfter?: number;
}

// ─── Redis client (lazy singleton) ───────────────────────────────────────────

type RedisLike = {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  ttl(key: string): Promise<number>;
  quit(): Promise<string>;
};

let _redis: RedisLike | null = null;
let _redisInitialized = false;

/** Returns the shared Redis client, or null when Redis is unavailable. */
async function getRedis(): Promise<RedisLike | null> {
  if (_redisInitialized) return _redis;
  _redisInitialized = true;

  const url = process.env.REDIS_URL;
  if (!url) {
    logger.info("[rate-limit] REDIS_URL not set — using in-memory fallback");
    return null;
  }

  try {
    // Dynamic import keeps ioredis out of the client bundle entirely.
    const { default: Redis } = await import("ioredis");
    const client = new Redis(url, {
      // Surface connection errors as events instead of crashing the process
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: 3000,
    });

    await client.connect();

    client.on("error", (err: Error) => {
      logger.error("[rate-limit] Redis error — falling back to memory", { error: err.message });
      _redis = null;
    });

    _redis = client;
    logger.info("[rate-limit] Redis connected");
    return _redis;
  } catch (err) {
    logger.warn("[rate-limit] Redis init failed — using in-memory fallback", {
      error: (err as Error).message,
    });
    return null;
  }
}

// ─── In-memory fallback ───────────────────────────────────────────────────────

/** { key → { count, expiresAt } } */
const memoryStore = new Map<string, { count: number; expiresAt: number }>();

function memoryRateLimit(key: string, opts: RateLimitOptions): RateLimitResult {
  const now = Date.now();
  const entry = memoryStore.get(key);

  if (!entry || entry.expiresAt <= now) {
    // First request in this window
    memoryStore.set(key, { count: 1, expiresAt: now + opts.windowMs });
    return { allowed: true };
  }

  if (entry.count >= opts.max) {
    const retryAfter = Math.max(1, Math.ceil((entry.expiresAt - now) / 1000));
    return { allowed: false, retryAfter };
  }

  entry.count += 1;
  return { allowed: true };
}

/** Exposed for test teardown — resets the in-memory store. */
export function resetMemoryRateLimitStore(): void {
  memoryStore.clear();
}

// ─── Redis fixed-window check ─────────────────────────────────────────────────

async function redisRateLimit(
  redis: RedisLike,
  key: string,
  opts: RateLimitOptions,
): Promise<RateLimitResult> {
  const redisKey = `rl:${key}`;
  const windowSec = Math.ceil(opts.windowMs / 1000);

  try {
    const count = await redis.incr(redisKey);

    if (count === 1) {
      // New window — set TTL
      await redis.expire(redisKey, windowSec);
    }

    if (count > opts.max) {
      const ttl = await redis.ttl(redisKey);
      const retryAfter = Math.max(1, ttl);
      return { allowed: false, retryAfter };
    }

    return { allowed: true };
  } catch (err) {
    // If Redis throws mid-request, degrade gracefully to memory
    logger.warn("[rate-limit] Redis command failed — using memory fallback for this request", {
      error: (err as Error).message,
    });
    return memoryRateLimit(key, opts);
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Check a rate limit for the given composite key.
 *
 * Uses Redis when available, in-memory store otherwise.
 *
 * @param key       Composite key, e.g. `"wallet:ip"` or `"ip:1.2.3.4"`
 * @param opts      Window and max-request options
 */
export async function checkRateLimit(
  key: string,
  opts: RateLimitOptions,
): Promise<RateLimitResult> {
  const redis = await getRedis();

  if (redis) {
    return redisRateLimit(redis, key, opts);
  }

  return memoryRateLimit(key, opts);
}

/** Reset the singleton so tests can inject a fresh state. */
export function _resetRedisClientForTesting(): void {
  _redis = null;
  _redisInitialized = false;
  memoryStore.clear();
}
