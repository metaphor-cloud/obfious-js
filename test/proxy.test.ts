/**
 * Tests for @obfious/js proxy — time-rotating URLs, key derivation, protect flow.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Obfious, parsePathShorthand } from "../src/proxy";

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

    it("includePaths uses segment-aware matching: /api matches /api/foo but not /apicrash", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api"] });
      // /apicrash is not a path under /api — should pass through unprotected
      expect((await ob.protect(new Request("https://example.com/apicrash"))).response).toBeNull();
      // /api/foo IS under /api — gets guarded (no auth header → 401)
      const result = await ob.protect(new Request("https://example.com/api/foo"));
      expect(result.response?.status).toBe(401);
    });

    it("includePaths /api/ (trailing slash) still matches /api/foo", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      const result = await ob.protect(new Request("https://example.com/api/foo"));
      expect(result.response?.status).toBe(401);
    });

    it("excludePaths uses segment-aware matching", async () => {
      const ob = new Obfious({ ...CREDS, excludePaths: ["/health"] });
      // /healthcheck is not under /health
      expect((await ob.protect(new Request("https://example.com/healthcheck"))).response?.status).toBe(401);
      // /health and /health/sub are excluded
      expect((await ob.protect(new Request("https://example.com/health"))).response).toBeNull();
      expect((await ob.protect(new Request("https://example.com/health/sub"))).response).toBeNull();
    });

    it("substitutes __PATH_MANIFEST__ with derived auth header name", async () => {
      const ob = new Obfious(CREDS);
      const scriptUrl = await ob.getScriptUrl();
      const [, qs] = scriptUrl.split("?");
      const [k, v] = qs.split("=");
      mockFetch.mockResolvedValueOnce(new Response("var X='__PATH_MANIFEST__';"));
      const result = await ob.protect(new Request("https://example.com" + scriptUrl));
      expect(await result.response!.text()).toBe(`var X='x-${k}-${v}';`);
    });

    it("rejects malformed paramValue even with a valid bootstrap key", async () => {
      // includePaths so root falls through to non-protected pass-through after the bundle check
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      const scriptUrl = await ob.getScriptUrl();
      const [, qs] = scriptUrl.split("?");
      const validKey = qs.split("=")[0];
      // paramValue contains a `"` — would break out of the bundle's JS string literal
      const evilUrl = `https://example.com/?${validKey}=evil%22+alert(1)+%22`;
      const result = await ob.protect(new Request(evilUrl));
      // Bundle MUST NOT be served — fetchBundle never called
      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.response).toBeNull();
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

    const RESYNC_NAME = "x-abcdef0123-deadbeef1234";
    const RESYNC_VALUE = "0123456789abcdef";

    it("relays resync headers verbatim from /validate response headers", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }), {
            headers: {
              "x-obf-resync-name": RESYNC_NAME,
              "x-obf-resync-value": RESYNC_VALUE,
            },
          });
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.deviceId).toBe("dev_abc");
      expect(result.resyncHeaders).toEqual({ [RESYNC_NAME]: RESYNC_VALUE });
    });

    it("returns botScore alongside resync headers", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", botScore: 0.15 }), {
            headers: {
              "x-obf-resync-name": RESYNC_NAME,
              "x-obf-resync-value": RESYNC_VALUE,
            },
          });
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.botScore).toBe(0.15);
      expect(result.resyncHeaders).toEqual({ [RESYNC_NAME]: RESYNC_VALUE });
    });

    it("no resyncHeaders when response headers absent", async () => {
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

    it("no resyncHeaders when only one of the two response headers is set", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }), {
            headers: { "x-obf-resync-name": RESYNC_NAME },
          });
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

    it("strips CRLF from resync headers (defence against header injection)", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      // The runtime Headers API rejects CRLF at construction, so use a shimmed Response
      // to simulate a non-conformant upstream and exercise sanitizeHeader directly.
      const headerMap: Record<string, string> = {
        "x-obf-resync-name": `${RESYNC_NAME}\rinjected`,
        "x-obf-resync-value": `${RESYNC_VALUE}\nx-evil: 1`,
      };
      const shimmedResponse = {
        ok: true,
        status: 200,
        headers: { get: (k: string) => headerMap[k.toLowerCase()] ?? null },
        json: async () => ({ valid: true, deviceId: "dev_abc" }),
      };
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate")) return shimmedResponse;
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      const [name, value] = Object.entries(result.resyncHeaders!)[0];
      expect(name).toBe(`${RESYNC_NAME}injected`);
      expect(value).toBe(`${RESYNC_VALUE}x-evil: 1`);
      expect(name + value).not.toMatch(/[\r\n]/);
    });

    it("rejects oversized resync header values (length cap)", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }), {
            headers: {
              "x-obf-resync-name": RESYNC_NAME,
              "x-obf-resync-value": "a".repeat(201),
            },
          });
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
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

  describe("parsePathShorthand", () => {
    it("plain prefix returns path with no method", () => {
      expect(parsePathShorthand("/api/")).toEqual({ path: "/api/" });
    });

    it("recognises known HTTP methods (case-insensitive, normalised to upper)", () => {
      expect(parsePathShorthand("post:/api/checkout")).toEqual({ path: "/api/checkout", method: "POST" });
      expect(parsePathShorthand("GET:/health")).toEqual({ path: "/health", method: "GET" });
      expect(parsePathShorthand("Patch:/items")).toEqual({ path: "/items", method: "PATCH" });
      expect(parsePathShorthand("OPTIONS:/x")).toEqual({ path: "/x", method: "OPTIONS" });
    });

    it("unknown method prefix is treated as literal path", () => {
      expect(parsePathShorthand("foo:/bar")).toEqual({ path: "foo:/bar" });
      expect(parsePathShorthand("CONNECT:/x")).toEqual({ path: "CONNECT:/x" });
    });

    it("colon beyond char 8 is treated as literal path", () => {
      // Colon at index 8 (just past the 0-7 window)
      expect(parsePathShorthand("/api/foo:bar")).toEqual({ path: "/api/foo:bar" });
    });

    it("colon at exactly char 8 is treated as literal", () => {
      // colonIdx must be < 8, so index 8 is out of range
      expect(parsePathShorthand("ABCDEFGH:/x")).toEqual({ path: "ABCDEFGH:/x" });
    });

    it("leading colon is treated as literal (no method prefix)", () => {
      expect(parsePathShorthand(":/x")).toEqual({ path: ":/x" });
    });
  });

  describe("method-qualified include/exclude paths", () => {
    it("plain prefix matches any method", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      // GET hits guard
      expect((await ob.protect(new Request("https://example.com/api/foo"))).response?.status).toBe(401);
      // POST hits guard too (no static ext, so falls through to guard)
      expect((await ob.protect(new Request("https://example.com/api/foo", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '{"x":1}',
      }))).response?.status).toBe(401);
    });

    it("method-qualified entry matches only when method AND path match", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["POST:/api/checkout"] });
      // POST /api/checkout: guarded → 401 with no auth header
      const post = await ob.protect(new Request("https://example.com/api/checkout", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '{"x":1}',
      }));
      expect(post.response?.status).toBe(401);
      // GET /api/checkout: wrong method → not in include list → pass through
      const get = await ob.protect(new Request("https://example.com/api/checkout"));
      expect(get.response).toBeNull();
    });

    it("method-qualified miss with wrong path falls through", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["POST:/api/checkout"] });
      const result = await ob.protect(new Request("https://example.com/other", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '{"x":1}',
      }));
      expect(result.response).toBeNull();
    });

    it("invalid method prefix is treated as literal path (no match)", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["foo:/bar"] });
      // Real path "/bar" with GET should NOT be guarded, since the entry literally
      // means the path "foo:/bar" which won't appear in any URL pathname
      const result = await ob.protect(new Request("https://example.com/bar"));
      expect(result.response).toBeNull();
    });

    it("colon beyond char 8 is treated as literal path", async () => {
      // "/api/foo:bar" has colon at index 8 (just past the window), literal path entry
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/foo:bar"] });
      // A request to /api/foo (no colon) should not match the literal entry
      expect((await ob.protect(new Request("https://example.com/api/foo"))).response).toBeNull();
      // A request to /api/foo:bar matches as a literal prefix → guarded
      expect((await ob.protect(new Request("https://example.com/api/foo:bar"))).response?.status).toBe(401);
    });

    it("excludePaths supports method-qualified entries", async () => {
      const ob = new Obfious({
        ...CREDS,
        includePaths: ["/api/"],
        excludePaths: ["GET:/api/health"],
      });
      // GET /api/health is excluded → pass through
      expect((await ob.protect(new Request("https://example.com/api/health"))).response).toBeNull();
      // POST /api/health: not excluded (wrong method) → falls into includes, guarded
      const post = await ob.protect(new Request("https://example.com/api/health", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: '{"x":1}',
      }));
      expect(post.response?.status).toBe(401);
    });
  });

  describe("network fingerprinting headers", () => {
    async function protectedRequest(ip?: string): Promise<Request> {
      const headerName = await buildAuthHeaderName(CREDS.secret);
      const payload = new Uint8Array(17);
      payload[0] = 0x21;
      payload.set([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04], 1);
      const b64 = btoa(String.fromCharCode(...payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const headers: Record<string, string> = { [headerName]: b64 + ".sig" };
      if (ip) headers["CF-Connecting-IP"] = ip;
      return new Request("https://example.com/api/data", { headers });
    }

    it("sends net headers on protocol POST from cf object and IPv4 IP", async () => {
      const ob = new Obfious(CREDS);
      let outboundHeaders: Headers | undefined;
      mockFetch.mockImplementation(async (_url: string, init: RequestInit) => {
        outboundHeaders = init.headers as Headers;
        return new Response("[]");
      });
      const req = new Request("https://example.com/static/config.json", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.42" },
        body: '["test"]',
      });
      (req as any).cf = { asn: 15169, country: "US" };
      await ob.protect(req);
      expect(outboundHeaders!.get("x-obfious-net-asn")).toBe("15169");
      expect(outboundHeaders!.get("x-obfious-net-country")).toBe("US");
      expect(outboundHeaders!.get("x-obfious-net-ip24")).toBe(btoa(String.fromCharCode(203, 0, 113, 0)));
    });

    it("omits x-obfious-net-ip24 for IPv6 and still sends ASN + country", async () => {
      const ob = new Obfious(CREDS);
      let outboundHeaders: Headers | undefined;
      mockFetch.mockImplementation(async (_url: string, init: RequestInit) => {
        outboundHeaders = init.headers as Headers;
        return new Response("[]");
      });
      const req = new Request("https://example.com/static/config.json", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "2001:db8::1" },
        body: '["test"]',
      });
      (req as any).cf = { asn: 15169, country: "US" };
      await ob.protect(req);
      expect(outboundHeaders!.get("x-obfious-net-ip24")).toBeNull();
      expect(outboundHeaders!.get("x-obfious-net-asn")).toBe("15169");
      expect(outboundHeaders!.get("x-obfious-net-country")).toBe("US");
    });

    it("sends net headers on /validate call", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      let validateHeaders: Headers | undefined;
      mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
        if (typeof url === "string" && url.includes("/validate")) {
          validateHeaders = init.headers as Headers;
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc" }));
        }
        return new Response("", { status: 404 });
      });
      const req = await protectedRequest("203.0.113.42");
      (req as any).cf = { asn: 15169, country: "US" };
      await ob.protect(req);
      expect(validateHeaders!.get("x-obfious-net-asn")).toBe("15169");
      expect(validateHeaders!.get("x-obfious-net-country")).toBe("US");
      expect(validateHeaders!.get("x-obfious-net-ip24")).toBe(btoa(String.fromCharCode(203, 0, 113, 0)));
    });

    it("omits ASN and country when no cf object is present, still sends ip24 for IPv4", async () => {
      const ob = new Obfious(CREDS);
      let outboundHeaders: Headers | undefined;
      mockFetch.mockImplementation(async (_url: string, init: RequestInit) => {
        outboundHeaders = init.headers as Headers;
        return new Response("[]");
      });
      const req = new Request("https://example.com/static/config.json", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.42" },
        body: '["test"]',
      });
      await ob.protect(req);
      expect(outboundHeaders!.get("x-obfious-net-asn")).toBeNull();
      expect(outboundHeaders!.get("x-obfious-net-country")).toBeNull();
      expect(outboundHeaders!.get("x-obfious-net-ip24")).toBe(btoa(String.fromCharCode(203, 0, 113, 0)));
    });

    it("omits x-obfious-net-ip24 for IPv4-mapped IPv6 addresses", async () => {
      const ob = new Obfious(CREDS);
      let outboundHeaders: Headers | undefined;
      mockFetch.mockImplementation(async (_url: string, init: RequestInit) => {
        outboundHeaders = init.headers as Headers;
        return new Response("[]");
      });
      const req = new Request("https://example.com/static/config.json", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "::ffff:203.0.113.42" },
        body: '["test"]',
      });
      await ob.protect(req);
      expect(outboundHeaders!.get("x-obfious-net-ip24")).toBeNull();
    });

    it("returns 401 for NETWORK_BLOCKED validate response", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockResolvedValue(
        new Response(JSON.stringify({ valid: false, reason: "NETWORK_BLOCKED" })),
      );
      const result = await ob.protect(await protectedRequest());
      expect(result.response!.status).toBe(401);
    });

    it("surfaces networkId from validate response", async () => {
      const ob = new Obfious({ ...CREDS, includePaths: ["/api/"] });
      mockFetch.mockImplementation(async (url: string) => {
        if (typeof url === "string" && url.includes("/validate"))
          return new Response(JSON.stringify({ valid: true, deviceId: "dev_abc", networkId: "net_abc123" }));
        return new Response("", { status: 404 });
      });
      const result = await ob.protect(await protectedRequest());
      expect(result.response).toBeNull();
      expect(result.networkId).toBe("net_abc123");
    });
  });
});
