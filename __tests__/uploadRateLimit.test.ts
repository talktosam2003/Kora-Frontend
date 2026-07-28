import { describe, it, expect, beforeEach, vi } from "vitest";
import { POST } from "@/app/api/upload/route";

// ─── Mock ioredis so tests never need a live Redis instance ──────────────────
// Must use a real class so `new Redis(url, opts)` works inside lib/rateLimit.ts
const _ioredisStore = new Map<string, { count: number; ttl: number }>();

vi.mock("ioredis", () => {
  class MockRedis {
    connect = vi.fn().mockResolvedValue(undefined);
    on = vi.fn();

    async incr(key: string): Promise<number> {
      const entry = _ioredisStore.get(key);
      if (!entry || Date.now() > entry.ttl) {
        _ioredisStore.set(key, { count: 1, ttl: Date.now() + 60_000 });
        return 1;
      }
      entry.count += 1;
      return entry.count;
    }

    async expire(key: string, ttlSec: number): Promise<number> {
      const entry = _ioredisStore.get(key);
      if (entry) entry.ttl = Date.now() + ttlSec * 1000;
      return 1;
    }

    async ttl(key: string): Promise<number> {
      const entry = _ioredisStore.get(key);
      if (!entry) return -2;
      return Math.max(0, Math.ceil((entry.ttl - Date.now()) / 1000));
    }

    async quit(): Promise<string> {
      return "OK";
    }
  }

  return { default: MockRedis };
});

// ─── Import after mock so the rate-limit module picks up the mocked ioredis ──
import { _resetRedisClientForTesting } from "@/lib/rateLimit";

/**
 * Reset both the Redis singleton and the mock store between tests so each
 * test starts with a clean slate.
 */
function resetAll() {
  _resetRedisClientForTesting();
  _ioredisStore.clear();
}

describe("Upload Route IP Rate Limiting", () => {
  beforeEach(() => {
    resetAll();
    process.env.PINATA_JWT = "mock-jwt";
    // Ensure Redis path is exercised by providing a URL
    process.env.REDIS_URL = "redis://localhost:6379";
  });

  it("allows up to 10 requests per minute and blocks the 11th", async () => {
    // Make 10 requests from the same IP
    for (let i = 0; i < 10; i++) {
      const req = new Request("https://kora.network/api/upload", {
        method: "POST",
        headers: {
          "x-forwarded-for": "1.2.3.4",
        },
      });
      const res = await POST(req as any);
      // Should NOT return 429 — may be 401/403/500 due to missing auth, but not rate-limited
      expect(res.status).not.toBe(429);
    }

    // 11th request should be blocked with 429
    const req11 = new Request("https://kora.network/api/upload", {
      method: "POST",
      headers: {
        "x-forwarded-for": "1.2.3.4",
      },
    });
    const res11 = await POST(req11 as any);
    expect(res11.status).toBe(429);
    expect(res11.headers.get("Retry-After")).toBeDefined();
    expect(Number(res11.headers.get("Retry-After"))).toBeGreaterThan(0);
  });

  it("handles multiple IPs independently", async () => {
    // IP 1 makes 10 requests
    for (let i = 0; i < 10; i++) {
      const req = new Request("https://kora.network/api/upload", {
        method: "POST",
        headers: {
          "x-forwarded-for": "1.1.1.1",
        },
      });
      const res = await POST(req as any);
      expect(res.status).not.toBe(429);
    }

    // IP 1 11th request is blocked
    const req1Block = new Request("https://kora.network/api/upload", {
      method: "POST",
      headers: {
        "x-forwarded-for": "1.1.1.1",
      },
    });
    const res1Block = await POST(req1Block as any);
    expect(res1Block.status).toBe(429);

    // IP 2 makes a request and is allowed
    const req2 = new Request("https://kora.network/api/upload", {
      method: "POST",
      headers: {
        "x-forwarded-for": "2.2.2.2",
      },
    });
    const res2 = await POST(req2 as any);
    expect(res2.status).not.toBe(429);
  });

  it("extracts the client IP from a comma-separated x-forwarded-for header", async () => {
    // Send 10 requests with client IP '9.9.9.9' proxy chain
    for (let i = 0; i < 10; i++) {
      const req = new Request("https://kora.network/api/upload", {
        method: "POST",
        headers: {
          "x-forwarded-for": "9.9.9.9, 10.0.0.1, 10.0.0.2",
        },
      });
      const res = await POST(req as any);
      expect(res.status).not.toBe(429);
    }

    // 11th request for '9.9.9.9' proxy chain is blocked
    const reqBlock = new Request("https://kora.network/api/upload", {
      method: "POST",
      headers: {
        "x-forwarded-for": "9.9.9.9, 10.0.0.1, 10.0.0.2",
      },
    });
    const resBlock = await POST(reqBlock as any);
    expect(resBlock.status).toBe(429);
  });

  it("falls back to memory store when REDIS_URL is not set", async () => {
    resetAll();
    delete process.env.REDIS_URL;

    // Should still enforce the IP limit using in-memory store
    for (let i = 0; i < 10; i++) {
      const req = new Request("https://kora.network/api/upload", {
        method: "POST",
        headers: { "x-forwarded-for": "5.5.5.5" },
      });
      const res = await POST(req as any);
      expect(res.status).not.toBe(429);
    }

    const req11 = new Request("https://kora.network/api/upload", {
      method: "POST",
      headers: { "x-forwarded-for": "5.5.5.5" },
    });
    const res11 = await POST(req11 as any);
    expect(res11.status).toBe(429);
    expect(Number(res11.headers.get("Retry-After"))).toBeGreaterThan(0);
  });
});
