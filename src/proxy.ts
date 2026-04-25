/**
 * Obfious v2.4 — Consumer proxy.
 *
 * Matches Obfious POST traffic by: POST + static file extension + JSON array body.
 * Forwards to API preserving the original random path.
 * Serves bootstrap script at time-rotating URL.
 */

export interface ObfiousConfig {
  /** Consumer key ID (required) */
  keyId: string;
  /** Consumer HMAC secret (required) */
  secret: string;
  /** Obfious API base URL (default: https://api.obfious.com) */
  apiUrl?: string;
  /** Override script URL instead of using time-rotating derivation */
  scriptPath?: string;
  /** Paths to protect (default: all) */
  includePaths?: string[];
  /** Paths to exclude from protection */
  excludePaths?: string[];
  /** Extract client IP */
  getClientIp?: (request: Request) => string;
  /** Extract platform signals (TLS, JA3, etc.) */
  getPlatformSignals?: (request: Request) => Record<string, string>;
  /** HMAC key for user identifier encryption */
  privateKey?: string;
  /**
   * Header name to read JA4 TLS fingerprint from (default: "x-cf-ja4").
   * Set this to match your reverse proxy's header (e.g. "X-JA4" for nginx).
   * On Cloudflare Workers, JA4 is also auto-extracted from request.cf.
   */
  jaHeaderName?: string;
}

export interface ObfiousCreds {
  keyId: string;
  secret: string;
}

export interface ProtectResult {
  response: Response | null;
  deviceId?: string;
  botScore?: number;
  resyncHeaders?: Record<string, string>;
}

const HDR_KEY = "x-obfious-key";
const HDR_SIG = "x-obfious-sig";
const HDR_TS = "x-obfious-ts";

declare const __OBFIOUS_VERSION__: string;
const PROXY_VERSION = `js/${typeof __OBFIOUS_VERSION__ !== "undefined" ? __OBFIOUS_VERSION__ : "unknown"}`;

const STATIC_EXT_RE = /\.(json|js|gif|png|woff2|css)$/;
const RANDOM_VALUE_TTL = 900_000; // 15 min

/** Fetch hook shim (~500 bytes). Hooks window.fetch immediately, queues same-origin
 *  requests until the full bootstrap activates via window.__obf_shim.r().
 *  - Cross-origin requests pass through immediately (proper URL origin check)
 *  - Respects AbortSignal on queued fetches
 *  - Falls back to native fetch after 15s if bootstrap never loads */
const SHIM_JS = `(function(){if(window.__obf_shim)return;var f=window.fetch.bind(window);var h,rr,p=new Promise(function(r){rr=r});var o=location.origin;function xo(i){try{var u=typeof i==="string"?i:(i instanceof URL?i.href:(i&&i.url||""));if(!u||u[0]==="/")return false;return new URL(u).origin!==o}catch(e){return false}}window.fetch=function(i,n){if(h)return h(i,n);if(xo(i))return f(i,n);var s=n&&n.signal;if(s&&s.aborted)return Promise.reject(new DOMException("The operation was aborted.","AbortError"));return new Promise(function(res,rej){var d=0;function ab(){if(!d){d=1;rej(new DOMException("The operation was aborted.","AbortError"))}}if(s)s.addEventListener("abort",ab);p.then(function(){if(s)s.removeEventListener("abort",ab);if(!d){d=1;res(h(i,n))}})})};setTimeout(function(){if(!h){h=f;rr()}},15000);window.__obf_shim={f:f,r:function(x){h=x;rr()}}})();`;

export class Obfious {
  private config: ObfiousConfig;
  private creds: ObfiousCreds;
  private randomValue: string | null = null;
  private randomValueCreatedAt = 0;
  private cachedKey: string | null = null;

  constructor(config: ObfiousConfig) {
    this.config = { ...config, apiUrl: config.apiUrl ?? "https://api.obfious.com" };
    this.creds = { keyId: config.keyId, secret: config.secret };
  }

  /** Get the script URL with time-rotating query param. */
  async getScriptUrl(): Promise<string> {
    if (this.config.scriptPath) return this.config.scriptPath;
    const key = await deriveKey(this.creds.secret, "obfious-bootstrap-v1");
    if (!this.randomValue || this.cachedKey !== key || Date.now() - this.randomValueCreatedAt > RANDOM_VALUE_TTL) {
      this.randomValue = await deriveObfValue(this.creds.secret, key);
      this.randomValueCreatedAt = Date.now();
      this.cachedKey = key;
    }
    return `/?${key}=${this.randomValue}`;
  }

  /** Get the shim script URL with time-rotating query param. */
  async getShimUrl(): Promise<string> {
    const key = await deriveKey(this.creds.secret, "obfious-shim-v1");
    return `/?${key}=1`;
  }

  /** Generate shim + bootstrap script tags. Shim: sync (tiny fetch hook). Bootstrap: async (non-blocking). */
  async scriptTag(opts?: { nonce?: string }): Promise<string> {
    const shimUrl = await this.getShimUrl();
    const bootstrapUrl = await this.getScriptUrl();
    // Standard CSP nonces are base64url; strip anything outside that set defensively.
    const safeNonce = opts?.nonce?.replace(/[^A-Za-z0-9+/=_-]/g, "");
    const nonceAttr = safeNonce ? ` nonce="${safeNonce}"` : "";
    return `<script src="${shimUrl}"${nonceAttr}></script>\n`
      + `<script src="${bootstrapUrl}" async fetchpriority="low"${nonceAttr}></script>`;
  }

  /** Main entry: handle a request */
  async protect(
    request: Request,
    user?: string,
  ): Promise<ProtectResult> {
    try {
      return await this._protect(request, user);
    } catch (err) {
      console.error("[obfious] unexpected error in protect, allowing request through:", err);
      return { response: null };
    }
  }

  private async _protect(request: Request, user?: string): Promise<ProtectResult> {
    const url = new URL(request.url);

    // --- Serve shim or bootstrap script ---
    if (request.method === "GET") {
      if (url.pathname === "/") {
        for (const [paramKey, paramValue] of url.searchParams) {
          // Shim: tiny fetch hook, served directly (no API call), cached 24h
          if (await isValidKey(this.creds.secret, "obfious-shim-v1", paramKey)) {
            return {
              response: new Response(SHIM_JS, {
                headers: {
                  "Content-Type": "application/javascript",
                  "Cache-Control": "private, max-age=86400",
                },
              }),
            };
          }
          if (await isValidKey(this.creds.secret, "obfious-bootstrap-v1", paramKey)) {
            // paramKey passed isValidKey; the bundle places paramValue inside a JS string
            // literal context. Bound paramValue to the format getScriptUrl emits so a hostile
            // URL can't inject JS via the placeholder substitution.
            if (!/^[0-9a-f]{8}[a-zA-Z0-9]{4}$/.test(paramValue)) continue;
            let bundle = await this.fetchBundle();
            // Inject auth header name derived from the bootstrap URL query params
            if (bundle) bundle = bundle.replace("__PATH_MANIFEST__", `x-${paramKey}-${paramValue}`);
            return {
              response: new Response(
                bundle ?? `console.error("[obfious] Failed to load bundle: ${this.lastFetchError}");`,
                {
                  headers: {
                    "Content-Type": "application/javascript",
                    "Cache-Control": bundle ? "private, max-age=300" : "no-store",
                  },
                },
              ),
            };
          }
        }
      }
      // Manual scriptPath override
      if (this.config.scriptPath && url.pathname === this.config.scriptPath) {
        const bundle = await this.fetchBundle();
        if (bundle) {
          return {
            response: new Response(bundle, {
              headers: {
                "Content-Type": "application/javascript",
                "Cache-Control": "no-store",
              },
            }),
          };
        }
      }
    }

    // --- Match Obfious POST traffic (JSON array) ---
    if (request.method === "POST" && STATIC_EXT_RE.test(url.pathname)) {
      const cloned = request.clone();
      const bodyBytes = new Uint8Array(await cloned.arrayBuffer());
      if (bodyBytes.length > 0 && bodyBytes[0] === 0x5B) { // '['
        return { response: await this.forwardToApi(request, url.pathname, bodyBytes) };
      }
    }

    // --- Guard protected routes ---
    if (this.config.excludePaths?.some(p => pathMatches(p, url.pathname))) return { response: null };
    if (this.config.includePaths) {
      if (!this.config.includePaths.some(p => pathMatches(p, url.pathname))) return { response: null };
    }

    const authHdr = await findAuthHeader(this.creds.secret, request);
    if (!authHdr) return { response: new Response(null, { status: 401 }) };

    const dot = authHdr.indexOf(".");
    if (dot < 1) return { response: new Response(null, { status: 401 }) };

    const payloadB64 = authHdr.slice(0, dot);
    const signatureB64 = authHdr.slice(dot + 1);
    const tokenHex = extractToken(payloadB64);
    if (!tokenHex) return { response: new Response(null, { status: 401 }) };

    const encryptedUser = (user && this.config.privateKey)
      ? await encryptUser(user, this.config.privateKey) : undefined;

    const result = await this.validateToken(tokenHex, payloadB64, signatureB64, encryptedUser);
    if (!result.valid) return { response: new Response(null, { status: 401 }) };

    return { response: null, deviceId: result.deviceId, botScore: result.botScore, resyncHeaders: result.resyncHeaders };
  }

  // --- Private ---

  private getIp(request: Request): string {
    if (this.config.getClientIp) return this.config.getClientIp(request);
    return request.headers.get("CF-Connecting-IP")
      || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim()
      || request.headers.get("X-Real-IP")
      || "unknown";
  }

  /** Extract JA4 TLS fingerprint from Cloudflare request.cf or configured header. */
  private extractJA4(request: Request): string | undefined {
    let ja4: string | undefined;

    // Cloudflare Workers: request.cf.botManagement.ja4
    const cf = (request as any).cf;
    const cfJa4 = cf?.botManagement?.ja4;
    if (cfJa4 && typeof cfJa4 === "string") {
      ja4 = cfJa4;
    }

    // Configured header fallback (default: x-cf-ja4). Useful behind nginx/HAProxy.
    if (!ja4) {
      const headerName = this.config.jaHeaderName || "x-cf-ja4";
      ja4 = request.headers.get(headerName) ?? undefined;
    }

    // Sanitize: strip CRLF and reject obviously invalid values
    if (ja4) {
      ja4 = ja4.replace(/[\r\n]/g, "");
      if (ja4.length > 200) return undefined;
    }
    return ja4 || undefined;
  }

  private lastFetchError = "";

  private async fetchBundle(): Promise<string | null> {
    try {
      const res = await this.authedFetch("/b", {
        method: "GET",
        headers: { "x-obfious-proxy-version": PROXY_VERSION },
      });
      if (!res.ok) {
        this.lastFetchError = `API returned ${res.status}`;
        console.error(`[obfious] Bundle fetch failed: ${res.status} ${res.statusText}`);
        return null;
      }
      return await res.text();
    } catch (err) {
      this.lastFetchError = `${err}`;
      console.error("[obfious] Bundle fetch error:", err);
      return null;
    }
  }

  private async forwardToApi(
    request: Request, originalPath: string, body: Uint8Array,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "x-obfious-ip": this.getIp(request),
    };

    // Custom platform signals callback (takes precedence)
    if (this.config.getPlatformSignals) {
      for (const [k, v] of Object.entries(this.config.getPlatformSignals(request))) {
        const key = k.replace(/[\r\n]/g, "").slice(0, 100);
        const val = String(v).replace(/[\r\n]/g, "").slice(0, 200);
        if (key && val) headers[key] = val;
      }
    }

    // Auto-extract JA4 if not already provided by getPlatformSignals.
    // Sources: Cloudflare request.cf (Workers) → configured header name.
    if (!("x-cf-ja4" in headers)) {
      const ja4 = this.extractJA4(request);
      if (ja4) headers["x-cf-ja4"] = ja4;
    }
    try {
      const res = await this.authedFetch(originalPath, {
        method: "POST",
        headers,
        body: body.buffer as ArrayBuffer,
      });
      if (!res.ok) {
        const errText = await res.clone().text().catch(() => "");
        console.error(`[obfious] forwardToApi ${originalPath}: ${res.status} ${errText}`);
      }
      return res;
    } catch (err) {
      console.error("[obfious] forwardToApi error, allowing request through:", err);
      return new Response(null, { status: 502 });
    }
  }

  private async validateToken(
    tokenHex: string, payloadB64: string, signatureB64: string, encryptedUser?: string,
  ): Promise<{ valid: boolean; deviceId?: string; resyncHeaders?: Record<string, string>; botScore?: number }> {
    try {
      const body: Record<string, any> = { tokenHex, signature: signatureB64, payload: payloadB64 };
      if (encryptedUser) body.encryptedUser = encryptedUser;
      const res = await this.authedFetch("/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        console.error(`[obfious] credential/API error during token validation (HTTP ${res.status}), allowing request through`);
        return { valid: true };
      }
      const result = await res.json() as any;
      if (result.valid !== true) {
        console.error(`[obfious] Validate rejected: ${JSON.stringify(result)}`);
      }
      const resyncName = sanitizeHeader(res.headers.get("x-obf-resync-name"));
      const resyncValue = sanitizeHeader(res.headers.get("x-obf-resync-value"));
      const resyncHeaders = (resyncName && resyncValue) ? { [resyncName]: resyncValue } : undefined;
      return { valid: result.valid === true, deviceId: result.deviceId, resyncHeaders, botScore: result.botScore };
    } catch (err) {
      console.error("[obfious] API unreachable during token validation, allowing request through:", err);
      return { valid: true };
    }
  }

  private async authedFetch(path: string, init: RequestInit): Promise<Response> {
    const url = `${this.config.apiUrl}${path}`;
    const ts = Date.now().toString();
    const method = (init.method || "GET").toUpperCase();
    const payload = `${ts}.${method}.${path}`;
    const sig = await hmacSign(this.creds!.secret, payload);

    const headers = new Headers(init.headers as HeadersInit);
    headers.set(HDR_KEY, this.creds!.keyId);
    headers.set(HDR_SIG, sig);
    headers.set(HDR_TS, ts);

    return fetch(url, { ...init, headers });
  }
}

// --- Time-rotating key derivation ---

async function deriveKey(secret: string, prefix: string, windowOffset = 0): Promise<string> {
  const window = Math.floor(Date.now() / 300_000) + windowOffset;
  return (await hmacSign(secret, prefix + ":" + window)).slice(0, 10);
}

async function isValidKey(secret: string, prefix: string, candidate: string): Promise<boolean> {
  if (candidate.length !== 10 || !/^[0-9a-f]{10}$/.test(candidate)) return false;
  for (const offset of [-1, 0, 1]) {
    if (await deriveKey(secret, prefix, offset) === candidate) return true;
  }
  return false;
}

// --- Helpers ---

function sanitizeHeader(v: string | null): string | undefined {
  if (!v) return undefined;
  const s = v.replace(/[\r\n]/g, "");
  if (!s || s.length > 200) return undefined;
  return s;
}

/** Constant-time string comparison. WebCrypto has no timingSafeEqual, so we
 *  XOR-accumulate to keep timing independent of where the first mismatch is. */
function ctEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Segment-aware path-prefix match. "/api" matches "/api" and "/api/foo" but not "/apicrash".
 *  A prefix that already ends in "/" matches any path under it. */
function pathMatches(prefix: string, pathname: string): boolean {
  if (!pathname.startsWith(prefix)) return false;
  if (pathname.length === prefix.length) return true;
  return prefix.endsWith("/") || pathname[prefix.length] === "/";
}

function hexEncode(buf: Uint8Array): string {
  return Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return hexEncode(new Uint8Array(sig));
}

async function encryptUser(user: string, privateKey: string): Promise<string> {
  return hmacSign(privateKey, user);
}

function extractToken(payloadB64: string): string | null {
  try {
    let b64 = payloadB64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    if (raw.length < 9 || raw[0] !== 0x21) return null;
    return hexEncode(raw.slice(1, 9));
  } catch {
    return null;
  }
}

function generateRandom(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}

// --- Auth header derivation ---

const HEX_CHARS = "0123456789abcdef";

function rotHex(s: string, n: number): string {
  return s.split("").map(c => {
    const i = HEX_CHARS.indexOf(c);
    if (i < 0) return c;
    return HEX_CHARS[(i + n) % 16];
  }).join("");
}

async function deriveObfValue(secret: string, domain: string): Promise<string> {
  const hmac8 = (await hmacSign(secret, domain)).slice(0, 8);
  const rotation = crypto.getRandomValues(new Uint8Array(1))[0] % 2 === 0 ? 13 : 14;
  return rotHex(hmac8, rotation) + generateRandom(4);
}

async function findAuthHeader(secret: string, request: Request): Promise<string | null> {
  for (const [name, value] of request.headers) {
    if (!name.startsWith("x-") || name.length < 14) continue;
    const rest = name.slice(2);
    const dashIdx = rest.indexOf("-");
    if (dashIdx < 1) continue;

    const keyPart = rest.slice(0, dashIdx);
    const valuePart = rest.slice(dashIdx + 1);
    if (!/^[0-9a-f]+$/.test(keyPart) || valuePart.length < 8) continue;

    const rotated8 = valuePart.slice(0, valuePart.length - 4);
    if (rotated8.length !== 8 || !/^[0-9a-f]{8}$/.test(rotated8)) continue;

    const expectedHmac = (await hmacSign(secret, keyPart)).slice(0, 8);
    if (ctEqual(rotHex(rotated8, 16 - 13), expectedHmac)) return value;
    if (ctEqual(rotHex(rotated8, 16 - 14), expectedHmac)) return value;

    // Fallback: value may have been derived from an adjacent-window key
    for (const offset of [-1, 1]) {
      const altKey = await deriveKey(secret, "obfious-bootstrap-v1", offset);
      const altHmac = (await hmacSign(secret, altKey)).slice(0, 8);
      if (ctEqual(rotHex(rotated8, 16 - 13), altHmac)) return value;
      if (ctEqual(rotHex(rotated8, 16 - 14), altHmac)) return value;
    }
  }
  return null;
}
