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
    it("returns shim (sync) + bootstrap (defer)", async () => {
      const ob = new Obfious(CREDS);
      const tags = await ob.scriptTag();
      const lines = tags.split("\n");
      expect(lines).toHaveLength(2);
      // Shim: no defer
      expect(lines[0]).toMatch(/^<script src="\/\?[0-9a-f]{10}=1"><\/script>$/);
      // Bootstrap: async, non-blocking
      expect(lines[1]).toMatch(/^<script src="\/\?[0-9a-f]{10}=[0-9a-f]{8}[a-zA-Z0-9]{4}" async fetchpriority="low"><\/script>$/);
    });

    it("includes nonce on both tags", async () => {
      const ob = new Obfious(CREDS);
      const tags = await ob.scriptTag({ nonce: "xyz" });
      const lines = tags.split("\n");
      expect(lines[0]).toContain('nonce="xyz"');
      expect(lines[1]).toContain('nonce="xyz"');
    });

    it("shim tag and bootstrap tag have different keys", async () => {
      const ob = new Obfious(CREDS);
      const tags = await ob.scriptTag();
      const lines = tags.split("\n");
      const shimKey = lines[0].match(/\?([0-9a-f]{10})=/)?.[1];
      const bootKey = lines[1].match(/\?([0-9a-f]{10})=/)?.[1];
      expect(shimKey).toBeDefined();
      expect(bootKey).toBeDefined();
      expect(shimKey).not.toBe(bootKey);
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

    it("returns botScore when validate includes it", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", botScore: 0.42 }));
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
      expect(result.botScore).toBe(0.42);
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

  describe("protect — resync headers", () => {
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

    it("derives resync headers when validate returns resync: true", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", resync: true }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.deviceId).toBe("dev_abc");
      expect(result.resyncHeaders).toBeDefined();
      const entries = Object.entries(result.resyncHeaders!);
      expect(entries).toHaveLength(1);
      const [name, value] = entries[0];
      // Header name: x-{10hex}-{8hex}{4alphanum}
      expect(name).toMatch(/^x-[0-9a-f]{10}-[0-9a-f]{8}[a-zA-Z0-9]{4}$/);
      // Value: 16 hex chars (HMAC tag)
      expect(value).toMatch(/^[0-9a-f]{16}$/);
    });

    it("resync header name uses bootstrap key prefix", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", resync: true }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      const scriptUrl = await ob.getScriptUrl();
      const bootstrapKey = scriptUrl.split("?")[1].split("=")[0];
      const resyncName = Object.keys(result.resyncHeaders!)[0];
      expect(resyncName.startsWith(`x-${bootstrapKey}-`)).toBe(true);
    });

    it("returns botScore alongside resync headers", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", resync: true, botScore: 0.15 }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.botScore).toBe(0.15);
      expect(result.resyncHeaders).toBeDefined();
    });

    it("no resyncHeaders when resync is absent", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.resyncHeaders).toBeUndefined();
    });

    it("no resyncHeaders when resync is explicitly false", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", resync: false }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.resyncHeaders).toBeUndefined();
    });

    it("no resyncHeaders on API error (fail-open)", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(new Response("Internal Server Error", { status: 500 }));
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.resyncHeaders).toBeUndefined();
    });
  });

  describe("shim — key derivation", () => {
    it("getShimUrl returns /?{10hex}=1", async () => {
      const ob = new Obfious(CREDS);
      expect(await ob.getShimUrl()).toMatch(/^\/\?[0-9a-f]{10}=1$/);
    });

    it("shim key differs from bootstrap key (same secret, same time)", async () => {
      const ob = new Obfious(CREDS);
      const shimUrl = await ob.getShimUrl();
      const bootUrl = await ob.getScriptUrl();
      const shimKey = shimUrl.split("?")[1].split("=")[0];
      const bootKey = bootUrl.split("?")[1].split("=")[0];
      expect(shimKey).not.toBe(bootKey);
    });

    it("shim key is stable across calls", async () => {
      const ob = new Obfious(CREDS);
      const u1 = await ob.getShimUrl();
      const u2 = await ob.getShimUrl();
      expect(u1).toBe(u2);
    });

    it("different secrets produce different shim keys", async () => {
      const u1 = await new Obfious({ keyId: "a", secret: "secret-a" }).getShimUrl();
      const u2 = await new Obfious({ keyId: "b", secret: "secret-b" }).getShimUrl();
      expect(u1.split("=")[0]).not.toBe(u2.split("=")[0]);
    });

    it("cross-language: shim key uses obfious-shim-v1 prefix", async () => {
      const ob = new Obfious({ keyId: "k", secret: VECTOR_SECRET });
      const shimUrl = await deriveWithFixedTime(() => ob.getShimUrl());
      const shimKey = shimUrl.split("?")[1].split("=")[0];
      // Shim key must differ from bootstrap key since different HMAC prefix
      expect(shimKey).not.toBe(VECTOR_BOOTSTRAP_KEY);
      expect(shimKey).toMatch(/^[0-9a-f]{10}$/);
    });
  });

  describe("shim — protect serving", () => {
    it("serves shim JS on valid shim key", async () => {
      const ob = new Obfious(CREDS);
      const shimUrl = "https://example.com" + await ob.getShimUrl();
      const result = await ob.protect(new Request(shimUrl));
      expect(result.response).not.toBeNull();
      const text = await result.response!.text();
      expect(text).toContain("__obf_shim");
      expect(result.response!.headers.get("Content-Type")).toBe("application/javascript");
    });

    it("shim has 24h cache", async () => {
      const ob = new Obfious(CREDS);
      const shimUrl = "https://example.com" + await ob.getShimUrl();
      const result = await ob.protect(new Request(shimUrl));
      expect(result.response!.headers.get("Cache-Control")).toBe("private, max-age=86400");
    });

    it("shim serving does not call API fetch", async () => {
      const ob = new Obfious(CREDS);
      const shimUrl = "https://example.com" + await ob.getShimUrl();
      await ob.protect(new Request(shimUrl));
      // mockFetch should NOT have been called (shim is served directly)
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("bootstrap still served on bootstrap key (not shim)", async () => {
      const ob = new Obfious(CREDS);
      const bootUrl = "https://example.com" + await ob.getScriptUrl();
      mockFetch.mockResolvedValueOnce(new Response("bundle-code"));
      const result = await ob.protect(new Request(bootUrl));
      expect(result.response).not.toBeNull();
      const text = await result.response!.text();
      expect(text).toBe("bundle-code");
      // Bootstrap fetches from API
      expect(mockFetch).toHaveBeenCalled();
    });
  });
});
