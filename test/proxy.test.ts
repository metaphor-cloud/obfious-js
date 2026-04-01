/**
 * Tests for @obfious/js proxy — time-rotating URLs, key derivation, protect flow.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Obfious } from "../src/proxy";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

const TEST_CREDS = { keyId: "k", secret: "test-secret" };

// --- Cross-language test vectors ---
// These must produce identical results in JS, Python, and Go.
// Secret: "test-secret-cross-lang", Window: 5765200
const VECTOR_SECRET = "test-secret-cross-lang";
const VECTOR_WINDOW = 5765200;
const VECTOR_BOOTSTRAP_KEY = "408a60c236";
const VECTOR_WORKER_KEY = "3w8e4851db";

// Helper: derive keys with a fixed timestamp (mock Date.now)
async function deriveWithFixedTime(fn: () => Promise<string>) {
  const original = Date.now;
  Date.now = () => VECTOR_WINDOW * 300_000; // window * 300s * 1000ms
  try {
    return await fn();
  } finally {
    Date.now = original;
  }
}

describe("@obfious/js proxy", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe("key derivation — cross-language vectors", () => {
    it("bootstrap key matches cross-language vector", async () => {
      const ob = new Obfious();
      ob["creds"] = { keyId: "k", secret: VECTOR_SECRET };
      const url = await deriveWithFixedTime(() => ob.getScriptUrl());
      const key = url.split("?")[1].split("=")[0];
      expect(key).toBe(VECTOR_BOOTSTRAP_KEY);
    });

    it("worker key matches cross-language vector", async () => {
      const ob = new Obfious();
      ob["creds"] = { keyId: "k", secret: VECTOR_SECRET };
      const url = await deriveWithFixedTime(() => ob.getWorkerUrl());
      const key = url.split("?")[1].split("=")[0];
      expect(key).toBe(VECTOR_WORKER_KEY);
    });
  });

  describe("key derivation — format", () => {
    it("getScriptUrl returns /?{10hex}={8alphanum}", async () => {
      const ob = new Obfious();
      ob["creds"] = TEST_CREDS;
      const url = await ob.getScriptUrl();
      expect(url).toMatch(/^\/\?[0-9a-f]{10}=[a-zA-Z0-9]{8}$/);
    });

    it("getWorkerUrl returns /?{10chars with w}={8alphanum}", async () => {
      const ob = new Obfious();
      ob["creds"] = TEST_CREDS;
      const url = await ob.getWorkerUrl();
      const key = url.split("?")[1].split("=")[0];
      expect(key).toHaveLength(10);
      expect(key).toContain("w");
      expect(key.split("w").length - 1).toBe(1);
    });

    it("same secret produces same bootstrap key within window", async () => {
      const ob1 = new Obfious();
      ob1["creds"] = TEST_CREDS;
      const ob2 = new Obfious();
      ob2["creds"] = TEST_CREDS;
      const u1 = await ob1.getScriptUrl();
      const u2 = await ob2.getScriptUrl();
      expect(u1.split("=")[0]).toBe(u2.split("=")[0]);
    });

    it("different secrets produce different keys", async () => {
      const ob1 = new Obfious();
      ob1["creds"] = { keyId: "a", secret: "secret-a" };
      const ob2 = new Obfious();
      ob2["creds"] = { keyId: "b", secret: "secret-b" };
      const u1 = await ob1.getScriptUrl();
      const u2 = await ob2.getScriptUrl();
      expect(u1.split("=")[0]).not.toBe(u2.split("=")[0]);
    });

    it("scriptPath override bypasses derivation", async () => {
      const ob = new Obfious({ scriptPath: "/custom.js" });
      expect(await ob.getScriptUrl()).toBe("/custom.js");
    });

    it("throws without credentials", async () => {
      const ob = new Obfious();
      await expect(ob.getScriptUrl()).rejects.toThrow("Credentials required");
    });
  });

  describe("scriptTag", () => {
    it("generates tag without defer", async () => {
      const ob = new Obfious({ scriptPath: "/test.js" });
      const tag = await ob.scriptTag();
      expect(tag).toBe('<script src="/test.js"></script>');
      expect(tag).not.toContain("defer");
    });

    it("includes nonce when provided", async () => {
      const ob = new Obfious({ scriptPath: "/test.js" });
      const tag = await ob.scriptTag({ nonce: "abc" });
      expect(tag).toBe('<script src="/test.js" nonce="abc"></script>');
    });
  });

  describe("protect — serve bootstrap and worker", () => {
    it("serves bundle on GET / with valid bootstrap key", async () => {
      const ob = new Obfious();
      const scriptUrl = "https://example.com" + await (async () => {
        ob["creds"] = TEST_CREDS;
        return await ob.getScriptUrl();
      })();

      mockFetch.mockResolvedValueOnce(new Response("bundle-code"));
      const req = new Request(scriptUrl);
      const result = await ob.protect(req, TEST_CREDS);

      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("bundle-code");
      expect(result.response!.headers.get("Content-Type")).toBe("application/javascript");
    });

    it("serves worker on GET / with valid worker key", async () => {
      const ob = new Obfious();
      const workerUrl = "https://example.com" + await (async () => {
        ob["creds"] = TEST_CREDS;
        return await ob.getWorkerUrl();
      })();

      mockFetch.mockResolvedValueOnce(new Response("worker-code"));
      const req = new Request(workerUrl);
      const result = await ob.protect(req, TEST_CREDS);

      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("worker-code");
    });

    it("passes through GET /", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      const req = new Request("https://example.com/");
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response).toBeNull();
    });

    it("passes through GET /?page=2", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      const req = new Request("https://example.com/?page=2");
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response).toBeNull();
    });
  });

  describe("protect — POST matching", () => {
    it("forwards POST with static ext + JSON array body", async () => {
      const ob = new Obfious();
      mockFetch.mockResolvedValueOnce(new Response("[]"));
      const req = new Request("https://example.com/static/config.json", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: '["test"]',
      });
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response).not.toBeNull();
      expect(mockFetch).toHaveBeenCalled();
    });

    it("does not forward POST without static extension", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      const req = new Request("https://example.com/api/data", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-req-auth": "" },
        body: '{"name":"test"}',
      });
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response!.status).toBe(401);
    });
  });

  describe("protect — auth", () => {
    it("returns 401 when x-req-auth missing", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      const req = new Request("https://example.com/api/data");
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response!.status).toBe(401);
    });

    it("validates token and returns deviceId", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate")) {
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }));
        }
        return new Response("", { status: 404 });
      });

      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      payload.set(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]), 1);
      const payloadB64 = btoa(String.fromCharCode(...payload))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

      const req = new Request("https://example.com/api/data", {
        headers: { "x-req-auth": payloadB64 + ".fakesig" },
      });
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response).toBeNull();
      expect(result.deviceId).toBe("dev_abc");
    });

    it("returns 401 on invalid validation", async () => {
      const ob = new Obfious({ includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response(JSON.stringify({ valid: false })));

      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      const payloadB64 = btoa(String.fromCharCode(...payload))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

      const req = new Request("https://example.com/api/data", {
        headers: { "x-req-auth": payloadB64 + ".badsig" },
      });
      const result = await ob.protect(req, TEST_CREDS);
      expect(result.response!.status).toBe(401);
    });
  });
});
