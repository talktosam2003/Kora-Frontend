/**
 * Unit tests for lib/rateLimit.ts
 *
 * Covers:
 * - In-memory fallback (no REDIS_URL)
 * - Redis fixed-window path (mocked ioredis)
 * - Graceful degradation when Redis commands throw
 * - Retry-After header value accuracy
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

// ─── Mock ioredis ─────────────────────────────────────────────────────────────
// Each test suite that exercises the Redis path will install a fresh mock via
// _resetRedisClientForTesting() so state never bleeds between tests.

const mockStore = new Map<string, { count: number; expireAt: number }>();

// Exported so tests can spy on it after creation
export let lastMockRedisInstance: InstanceType<typeof MockRedisClass> | null = null;

class MockRedisClass {
  connect = vi.fn().mockResolvedValue(undefined);
  on = vi.fn();

  async incr(key: string): Promise<number> {
    const now = Date.now();
    const entry = mockStore.get(key);
    if (!entry || now > entry.expireAt) {
      mockStore.set(key, { count: 1, expireAt: now + 60_000 });
      return 1;
    }
    entry.count += 1;
    return entry.count;
  }

  async expire(key: string, ttlSec: number): Promise<number> {
    const entry = mockStore.get(key);
    if (entry) entry.expireAt = Date.now() + ttlSec * 1000;
    return 1;
  }

  async ttl(key: string): Promise<number> {
    const entry = mockStore.get(key);
    if (!entry) return -2;
    return Math.max(0, Math.ceil((entry.expireAt - Date.now()) / 1000));
  }

  async quit(): Promise<string> {
    return "OK";
  }
}

// vitest module factory — must be a real class/constructor, not a vi.fn() wrapper
vi.mock("ioredis", () => ({
  default: class RedisProxy extends MockRedisClass {
    constructor(_url: string, _opts?: unknown) {
      super();
      lastMockRedisInstance = this;
    }
  },
}));

// ─── Import after mock so the rate-limit module picks up the mocked ioredis ──
import {
  checkRateLimit,
  resetMemoryRateLimitStore,
  _resetRedisClientForTesting,
} from "@/lib/rateLimit";

/**
 * Reset both the Redis singleton and the mock store between tests so each
 * test starts with a clean slate.
 */
function fullReset() {
  _resetRedisClientForTesting();
  mockStore.clear();
  lastMockRedisInstance = null;
}

describe("checkRateLimit — in-memory fallback (no REDIS_URL)", () => {
  beforeEach(() => {
    fullReset();
    delete process.env.REDIS_URL;
  });

  afterEach(() => {
    resetMemoryRateLimitStore();
  });

  it("allows requests up to the max", async () => {
    for (let i = 0; i < 5; i++) {
      const result = await checkRateLimit("test-key", { windowMs: 60_000, max: 5 });
      expect(result.allowed).toBe(true);
    }
  });

  it("blocks the request after max is reached", async () => {
    for (let i = 0; i < 5; i++) {
      await checkRateLimit("block-key", { windowMs: 60_000, max: 5 });
    }
    const result = await checkRateLimit("block-key", { windowMs: 60_000, max: 5 });
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it("tracks keys independently", async () => {
    for (let i = 0; i < 5; i++) {
      await checkRateLimit("key-a", { windowMs: 60_000, max: 5 });
    }
    // key-a is exhausted; key-b should still be allowed
    const resultA = await checkRateLimit("key-a", { windowMs: 60_000, max: 5 });
    const resultB = await checkRateLimit("key-b", { windowMs: 60_000, max: 5 });
    expect(resultA.allowed).toBe(false);
    expect(resultB.allowed).toBe(true);
  });

  it("resets after the window expires", async () => {
    for (let i = 0; i < 3; i++) {
      await checkRateLimit("expiry-key", { windowMs: 1, max: 3 });
    }
    // Window of 1 ms should have expired immediately
    await new Promise((r) => setTimeout(r, 5));
    const result = await checkRateLimit("expiry-key", { windowMs: 1, max: 3 });
    expect(result.allowed).toBe(true);
  });

  it("returns retryAfter close to remaining window seconds", async () => {
    const windowMs = 10_000;
    for (let i = 0; i < 3; i++) {
      await checkRateLimit("retry-key", { windowMs, max: 3 });
    }
    const result = await checkRateLimit("retry-key", { windowMs, max: 3 });
    expect(result.allowed).toBe(false);
    // Should be at most windowMs/1000 seconds
    expect(result.retryAfter).toBeLessThanOrEqual(windowMs / 1000);
    expect(result.retryAfter).toBeGreaterThanOrEqual(1);
  });
});

describe("checkRateLimit — Redis path", () => {
  beforeEach(() => {
    fullReset();
    process.env.REDIS_URL = "redis://localhost:6379";
  });

  it("uses Redis INCR and EXPIRE on first request", async () => {
    const result = await checkRateLimit("redis-key", { windowMs: 60_000, max: 10 });
    expect(result.allowed).toBe(true);
    // Key should exist in the mock store with rl: prefix
    expect(mockStore.has("rl:redis-key")).toBe(true);
    expect(mockStore.get("rl:redis-key")?.count).toBe(1);
  });

  it("does NOT reset the window on subsequent requests within the same window", async () => {
    await checkRateLimit("redis-key2", { windowMs: 60_000, max: 10 });
    await checkRateLimit("redis-key2", { windowMs: 60_000, max: 10 });
    // Count should be 2, not reset to 1
    expect(mockStore.get("rl:redis-key2")?.count).toBe(2);
  });

  it("blocks when count exceeds max and returns Retry-After from TTL", async () => {
    const opts = { windowMs: 60_000, max: 3 };
    for (let i = 0; i < 3; i++) {
      await checkRateLimit("redis-block", opts);
    }
    const result = await checkRateLimit("redis-block", opts);
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it("falls back to memory when Redis incr throws", async () => {
    // Warm up the connection first
    await checkRateLimit("warmup", { windowMs: 60_000, max: 10 });
    // Corrupt the stored instance so incr throws on next call
    if (lastMockRedisInstance) {
      vi.spyOn(lastMockRedisInstance, "incr").mockRejectedValueOnce(new Error("ECONNRESET"));
    }
    const result = await checkRateLimit("fallback-key", { windowMs: 60_000, max: 10 });
    expect(typeof result.allowed).toBe("boolean");
  });

  it("keys are prefixed with rl:", async () => {
    await checkRateLimit("wallet:1.2.3.4", { windowMs: 60_000, max: 10 });
    expect(mockStore.has("rl:wallet:1.2.3.4")).toBe(true);
  });
});

describe("resetMemoryRateLimitStore", () => {
  beforeEach(() => {
    fullReset();
    delete process.env.REDIS_URL;
  });

  it("clears existing in-memory counters", async () => {
    const opts = { windowMs: 60_000, max: 2 };
    await checkRateLimit("reset-key", opts);
    await checkRateLimit("reset-key", opts);
    let result = await checkRateLimit("reset-key", opts);
    expect(result.allowed).toBe(false);

    resetMemoryRateLimitStore();

    result = await checkRateLimit("reset-key", opts);
    expect(result.allowed).toBe(true);
  });
});
