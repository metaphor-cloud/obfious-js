/**
 * Tests for @obfious/js proxy — time-rotating URLs, key derivation, protect flow.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Obfious } from "../src/proxy";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

const CREDS = { keyId: "k", secret: "test-secret" };

// Helper: build a valid derived auth header name for testing
const HEX_CHARS = "0123456789abcdef";
function rotHex(s: string, n: number): string {
  return s.split("").map(c => {
    const i = HEX_CHARS.indexOf(c);
    return i < 0 ? c : HEX_CHARS[(i + n) % 16];
  }).join("");
}
async function buildAuthHeaderName(secret: string): Promise<string> {
  const window = Math.floor(Date.now() / 300_000);
  const keyBytes = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const keySig = await crypto.subtle.sign("HMAC", keyBytes, new TextEncoder().encode("obfious-bootstrap-v1:" + window));
  const bootstrapKey = Array.from(new Uint8Array(keySig), b => b.toString(16).padStart(2, "0")).join("").slice(0, 10);
  const valSig = await crypto.subtle.sign("HMAC", keyBytes, new TextEncoder().encode(bootstrapKey));
  const hmac8 = Array.from(new Uint8Array(valSig), b => b.toString(16).padStart(2, "0")).join("").slice(0, 8);
  return `x-${bootstrapKey}-${rotHex(hmac8, 13)}abcd`;
}

// Cross-language test vectors
const VECTOR_SECRET = "test-secret-cross-lang";
const VECTOR_WINDOW = 5765200;
const VECTOR_BOOTSTRAP_KEY = "408a60c236";

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
  });

  describe("key derivation", () => {
    it("getScriptUrl returns /?{10hex}={12chars}", async () => {
      const ob = new Obfious(CREDS);
      expect(await ob.getScriptUrl()).toMatch(/^\/\?[0-9a-f]{10}=[0-9a-f]{8}[a-zA-Z0-9]{4}$/);
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

  describe("protect — bootstrap", () => {
    it("serves bundle on valid bootstrap key", async () => {
      const ob = new Obfious(CREDS);
      const url = "https://example.com" + await ob.getScriptUrl();
      mockFetch.mockResolvedValueOnce(new Response("bundle"));
      const result = await ob.protect(new Request(url));
      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("bundle");
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
        method: "POST", headers: { "Content-Type": "application/json" },
        body: '{"name":"test"}',
      }));
      expect(result.response!.status).toBe(401);
    });
  });

  describe("middleware creds flow", () => {
    it("creds passed via middleware pattern reach the constructor", async () => {
      // Simulate the Express/Fastify/Lambda pattern:
      // { creds, ...config } destructured, then keyId/secret added back
      const creds = { keyId: "k", secret: "test-secret" };
      const config = { includePaths: ["/api/"] };
      const ob = new Obfious({ ...config, keyId: creds.keyId, secret: creds.secret });

      // If creds flowed correctly, the bootstrap key should match one built with direct creds
      const directOb = new Obfious({ keyId: "k", secret: "test-secret" });
      const url1 = (await ob.getScriptUrl()).split("=")[0];
      const url2 = (await directOb.getScriptUrl()).split("=")[0];
      expect(url1).toBe(url2);
    });

    it("serves bundle when creds come from middleware pattern", async () => {
      const creds = { keyId: "k", secret: "test-secret" };
      const ob = new Obfious({ keyId: creds.keyId, secret: creds.secret });
      const url = "https://example.com" + await ob.getScriptUrl();
      mockFetch.mockResolvedValueOnce(new Response("bundle"));
      const result = await ob.protect(new Request(url));
      expect(result.response).not.toBeNull();
      expect(await result.response!.text()).toBe("bundle");
    });
  });

  describe("protect — auth", () => {
    it("401 when no valid auth header present", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      expect((await ob.protect(new Request("https://example.com/api/data"))).response!.status).toBe(401);
    });

    it("validates token + returns deviceId with derived header", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }));
        return new Response("", { status: 404 });
      });
      const headerName = await buildAuthHeaderName(CREDS.secret);
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      payload.set([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04], 1);
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const result = await ob.protect(new Request("https://example.com/api/data", {
        headers: { [headerName]: b64 + ".sig" },
      }));
      expect(result.response).toBeNull();
      expect(result.deviceId).toBe("dev_abc");
    });

    it("401 on invalid validation", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response(JSON.stringify({ valid: false })));
      const headerName = await buildAuthHeaderName(CREDS.secret);
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const result = await ob.protect(new Request("https://example.com/api/data", {
        headers: { [headerName]: b64 + ".bad" },
      }));
      expect(result.response!.status).toBe(401);
    });
  });

  describe("graceful degradation", () => {
    async function protectedRequest(): Promise<Request> {
      const headerName = await buildAuthHeaderName(CREDS.secret);
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      payload.set([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04], 1);
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      return new Request("https://example.com/api/data", {
        headers: { [headerName]: b64 + ".sig" },
      });
    }

    it("passes through when /validate returns 500", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response("Internal Server Error", { status: 500 }));
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
    });

    it("passes through when /validate returns 403 (bad creds)", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response("Forbidden", { status: 403 }));
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
    });

    it("passes through on network error", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockRejectedValue(new Error("fetch failed"));
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
    });

    it("still blocks when API returns 200 with valid: false", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response(JSON.stringify({ valid: false })));
      const result = await ob.protect(await protectedRequest());
      expect(result.response!.status).toBe(401);
    });

    it("forwardToApi returns 502 on network error", async () => {
      const ob = new Obfious(CREDS);
      mockFetch.mockRejectedValue(new Error("connection refused"));
      const result = await ob.protect(new Request("https://example.com/static/config.json", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '["test"]',
      }));
      expect(result.response).not.toBeNull();
      expect(result.response!.status).toBe(502);
    });
  });
});
