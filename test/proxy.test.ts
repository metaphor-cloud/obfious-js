/**
 * Tests for @obfious/js proxy — time-rotating URLs, key derivation, protect flow.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Obfious } from "../src/proxy";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

const CREDS = { keyId: "k", secret: "test-secret" };

// Cross-language test vectors
const VECTOR_SECRET = "test-secret-cross-lang";
const VECTOR_WINDOW = 5765200;
const VECTOR_BOOTSTRAP_KEY = "408a60c236";
const VECTOR_WORKER_KEY = "3w8e4851db";

async function deriveWithFixedTime(fn: () => Promise<string>) {
  const original = Date.now;
  Date.now = () => VECTOR_WINDOW * 300_000;
  try { return await fn(); }
  finally { Date.now = original; }
}

describe("@obfious/js proxy", () => {
  beforeEach(() => { mockFetch.mockReset(); });

  describe("cross-language vectors", () => {
    it("bootstrap key matches", async () => {
      const ob = new Obfious({ keyId: "k", secret: VECTOR_SECRET });
      const url = await deriveWithFixedTime(() => ob.getScriptUrl());
      expect(url.split("?")[1].split("=")[0]).toBe(VECTOR_BOOTSTRAP_KEY);
    });

    it("worker key matches", async () => {
      const ob = new Obfious({ keyId: "k", secret: VECTOR_SECRET });
      const url = await deriveWithFixedTime(() => ob.getWorkerUrl());
      expect(url.split("?")[1].split("=")[0]).toBe(VECTOR_WORKER_KEY);
    });
  });

  describe("key derivation", () => {
    it("getScriptUrl returns /?{10hex}={8alphanum}", async () => {
      const ob = new Obfious(CREDS);
      expect(await ob.getScriptUrl()).toMatch(/^\/\?[0-9a-f]{10}=[a-zA-Z0-9]{8}$/);
    });

    it("getWorkerUrl has 10 chars with 'w'", async () => {
      const ob = new Obfious(CREDS);
      const key = (await ob.getWorkerUrl()).split("?")[1].split("=")[0];
      expect(key).toHaveLength(10);
      expect(key).toContain("w");
    });

    it("same secret = same key", async () => {
      const u1 = await new Obfious(CREDS).getScriptUrl();
      const u2 = await new Obfious(CREDS).getScriptUrl();
      expect(u1.split("=")[0]).toBe(u2.split("=")[0]);
    });

    it("different secrets = different keys", async () => {
      const u1 = await new Obfious({ keyId: "a", secret: "secret-a" }).getScriptUrl();
      const u2 = await new Obfious({ keyId: "b", secret: "secret-b" }).getScriptUrl();
      expect(u1.split("=")[0]).not.toBe(u2.split("=")[0]);
    });

    it("scriptPath override", async () => {
      const ob = new Obfious({ ...CREDS, scriptPath: "/custom.js" });
      expect(await ob.getScriptUrl()).toBe("/custom.js");
    });
  });

  describe("scriptTag", () => {
    it("no defer", async () => {
      const ob = new Obfious({ ...CREDS, scriptPath: "/test.js" });
      expect(await ob.scriptTag()).toBe('<script src="/test.js"></script>');
    });

    it("nonce", async () => {
      const ob = new Obfious({ ...CREDS, scriptPath: "/test.js" });
      expect(await ob.scriptTag({ nonce: "abc" }))
        .toBe('<script src="/test.js" nonce="abc"></script>');
    });
  });

  describe("protect — bootstrap/worker", () => {
    it("serves bundle on valid bootstrap key", async () => {
      const ob = new Obfious(CREDS);
      const url = "https://example.com" + await ob.getScriptUrl();
      mockFetch.mockResolvedValueOnce(new Response("bundle"));
      const result = await ob.protect(new Request(url));
      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("bundle");
    });

    it("serves worker on valid worker key", async () => {
      const ob = new Obfious(CREDS);
      const url = "https://example.com" + await ob.getWorkerUrl();
      mockFetch.mockResolvedValueOnce(new Response("worker"));
      const result = await ob.protect(new Request(url));
      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("worker");
    });

    it("passes through GET /", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      expect((await ob.protect(new Request("https://example.com/"))).response).toBeNull();
    });

    it("passes through GET /?page=2", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      expect((await ob.protect(new Request("https://example.com/?page=2"))).response).toBeNull();
    });
  });

  describe("protect — POST matching", () => {
    it("forwards POST + static ext + JSON array", async () => {
      const ob = new Obfious(CREDS);
      mockFetch.mockResolvedValueOnce(new Response("[]"));
      const result = await ob.protect(new Request("https://example.com/static/config.json", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '["test"]',
      }));
      expect(result.response).not.toBeNull();
    });

    it("401 on POST without static ext", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      const result = await ob.protect(new Request("https://example.com/api/data", {
        method: "POST", headers: { "Content-Type": "application/json", "x-req-auth": "" },
        body: '{"name":"test"}',
      }));
      expect(result.response!.status).toBe(401);
    });
  });

  describe("protect — auth", () => {
    it("401 when x-req-auth missing", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      expect((await ob.protect(new Request("https://example.com/api/data"))).response!.status).toBe(401);
    });

    it("validates token + returns deviceId", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }));
        return new Response("", { status: 404 });
      });
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      payload.set([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04], 1);
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const result = await ob.protect(new Request("https://example.com/api/data", {
        headers: { "x-req-auth": b64 + ".sig" },
      }));
      expect(result.response).toBeNull();
      expect(result.deviceId).toBe("dev_abc");
    });

    it("401 on invalid validation", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response(JSON.stringify({ valid: false })));
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const result = await ob.protect(new Request("https://example.com/api/data", {
        headers: { "x-req-auth": b64 + ".bad" },
      }));
      expect(result.response!.status).toBe(401);
    });
  });
});
