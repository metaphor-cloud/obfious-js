/**
 * Obfious v2.2 — Consumer proxy.
 *
 * Matches Obfious POST traffic by: POST + static file extension + JSON array body.
 * Forwards to API preserving the original random path.
 * Serves bootstrap script and worker at time-rotating URLs.
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
}

export interface ObfiousCreds {
  keyId: string;
  secret: string;
}

export interface ProtectResult {
  response: Response | null;
  deviceId?: string;
}

const HDR_KEY = "x-obfious-key";
const HDR_SIG = "x-obfious-sig";
const HDR_TS = "x-obfious-ts";

const STATIC_EXT_RE = /\.(json|js|gif|png|woff2|css)$/;
const RANDOM_VALUE_TTL = 900_000; // 15 min

export class Obfious {
  private config: ObfiousConfig;
  private creds: ObfiousCreds;
  private randomValue: string | null = null;
  private randomValueCreatedAt = 0;

  constructor(config: ObfiousConfig) {
    this.config = { ...config, apiUrl: config.apiUrl ?? "https://api.obfious.com" };
    this.creds = { keyId: config.keyId, secret: config.secret };
  }

  /** Get the script URL with time-rotating query param. */
  async getScriptUrl(): Promise<string> {
    if (this.config.scriptPath) return this.config.scriptPath;
    const key = await deriveBootstrapKey(this.creds.secret);
    this.ensureRandomValue();
    return `/?${key}=${this.randomValue}`;
  }

  /** Get the worker URL with time-rotating query param (includes type marker). */
  async getWorkerUrl(): Promise<string> {
    const key = await deriveWorkerKey(this.creds.secret);
    this.ensureRandomValue();
    return `/?${key}=${this.randomValue}`;
  }

  /** Generate script tag HTML — no defer, must load in <head> before other scripts. */
  async scriptTag(opts?: { nonce?: string }): Promise<string> {
    const url = await this.getScriptUrl();
    const nonceAttr = opts?.nonce ? ` nonce="${opts.nonce}"` : "";
    return `<script src="${url}"${nonceAttr}></script>`;
  }

  /** Main entry: handle a request */
  async protect(
    request: Request,
    user?: string,
  ): Promise<ProtectResult> {

    const url = new URL(request.url);

    // --- Serve bootstrap script or worker ---
    if (request.method === "GET") {
      if (url.pathname === "/") {
        for (const [paramKey] of url.searchParams) {
          if (await isValidBootstrapKey(this.creds.secret, paramKey)) {
            const bundle = await this.fetchBundle();
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
          if (await isValidWorkerKey(this.creds.secret, paramKey)) {
            const worker = await this.fetchWorker();
            return {
              response: new Response(
                worker ?? `console.error("[obfious] Failed to load worker: ${this.lastFetchError}");`,
                {
                  headers: {
                    "Content-Type": "application/javascript",
                    "Cache-Control": worker ? "private, max-age=300" : "no-store",
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

    // --- Match Obfious POST traffic ---
    if (request.method === "POST" && STATIC_EXT_RE.test(url.pathname)) {
      const contentType = request.headers.get("Content-Type") || "";
      if (contentType === "application/octet-stream") {
        return { response: await this.forwardStreamToApi(request, url.pathname) };
      }
      const cloned = request.clone();
      const bodyBytes = new Uint8Array(await cloned.arrayBuffer());
      if (bodyBytes.length > 0 && bodyBytes[0] === 0x5B) { // '['
        return { response: await this.forwardToApi(request, url.pathname, bodyBytes) };
      }
    }

    // --- Guard protected routes ---
    if (this.config.excludePaths?.some(p => url.pathname.startsWith(p))) return { response: null };
    if (this.config.includePaths) {
      if (!this.config.includePaths.some(p => url.pathname.startsWith(p))) return { response: null };
    }

    const authHdr = request.headers.get("x-req-auth");
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

    return { response: null, deviceId: result.deviceId };
  }

  // --- Private ---

  private ensureRandomValue(): void {
    if (!this.randomValue || Date.now() - this.randomValueCreatedAt > RANDOM_VALUE_TTL) {
      this.randomValue = generateRandom(8);
      this.randomValueCreatedAt = Date.now();
    }
  }

  private getIp(request: Request): string {
    if (this.config.getClientIp) return this.config.getClientIp(request);
    return request.headers.get("CF-Connecting-IP")
      || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim()
      || request.headers.get("X-Real-IP")
      || "unknown";
  }

  private lastFetchError = "";

  private async fetchBundle(): Promise<string | null> {
    try {
      const workerUrl = await this.getWorkerUrl();
      const res = await this.authedFetch("/b", {
        method: "GET",
        headers: { "x-obfious-worker-url": workerUrl },
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

  private async fetchWorker(): Promise<string | null> {
    try {
      const res = await this.authedFetch("/w", { method: "GET" });
      if (!res.ok) {
        this.lastFetchError = `API returned ${res.status}`;
        console.error(`[obfious] Worker fetch failed: ${res.status} ${res.statusText}`);
        return null;
      }
      return await res.text();
    } catch (err) {
      this.lastFetchError = `${err}`;
      console.error("[obfious] Worker fetch error:", err);
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
    if (this.config.getPlatformSignals) {
      for (const [k, v] of Object.entries(this.config.getPlatformSignals(request))) {
        headers[k.replace(/[\r\n]/g, "")] = String(v).replace(/[\r\n]/g, "");
      }
    }
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
  }

  private async forwardStreamToApi(
    request: Request, originalPath: string,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
      "x-obfious-ip": this.getIp(request),
    };
    if (this.config.getPlatformSignals) {
      for (const [k, v] of Object.entries(this.config.getPlatformSignals(request))) {
        headers[k.replace(/[\r\n]/g, "")] = String(v).replace(/[\r\n]/g, "");
      }
    }
    try {
      const res = await this.authedFetch(originalPath, {
        method: "POST",
        headers,
        body: request.body ?? undefined,
      });
      console.log(`[obfious] Stream proxy: API responded ${res.status}, body=${!!res.body}`);
      return res;
    } catch (err) {
      console.error("[obfious] Stream proxy error:", err);
      return new Response(null, { status: 502 });
    }
  }

  private async validateToken(
    tokenHex: string, payloadB64: string, signatureB64: string, encryptedUser?: string,
  ): Promise<{ valid: boolean; deviceId?: string }> {
    try {
      const body: Record<string, any> = { tokenHex, signature: signatureB64, payload: payloadB64 };
      if (encryptedUser) body.encryptedUser = encryptedUser;
      const res = await this.authedFetch("/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        console.error(`[obfious] Validate failed: ${res.status} ${errText}`);
        return { valid: false };
      }
      const result = await res.json() as any;
      if (result.valid !== true) {
        console.error(`[obfious] Validate rejected: ${JSON.stringify(result)}`);
      }
      return { valid: result.valid === true, deviceId: result.deviceId };
    } catch (err) {
      console.error("[obfious] Validate error:", err);
      return { valid: false };
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

async function deriveBootstrapKey(secret: string, windowOffset = 0): Promise<string> {
  const window = Math.floor(Date.now() / 300_000) + windowOffset;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode("obfious-bootstrap-v1:" + window),
  );
  return hexEncode(new Uint8Array(sig)).slice(0, 10);
}

async function isValidBootstrapKey(secret: string, candidate: string): Promise<boolean> {
  if (candidate.length !== 10 || !/^[0-9a-f]{10}$/.test(candidate)) return false;
  for (const offset of [-1, 0, 1]) {
    if (await deriveBootstrapKey(secret, offset) === candidate) return true;
  }
  return false;
}

async function deriveWorkerKey(secret: string, windowOffset = 0): Promise<string> {
  const window = Math.floor(Date.now() / 300_000) + windowOffset;
  const position = (window % 7) + 1;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode("obfious-worker-v1:" + window),
  );
  const hex = hexEncode(new Uint8Array(sig)).slice(0, 9);
  return hex.slice(0, position) + "w" + hex.slice(position);
}

async function isValidWorkerKey(secret: string, candidate: string): Promise<boolean> {
  if (candidate.length !== 10) return false;
  const wIdx = candidate.indexOf("w");
  if (wIdx < 1 || wIdx > 7) return false;
  if (candidate.lastIndexOf("w") !== wIdx) return false;
  const withoutW = candidate.slice(0, wIdx) + candidate.slice(wIdx + 1);
  if (!/^[0-9a-f]{9}$/.test(withoutW)) return false;
  for (const offset of [-1, 0, 1]) {
    if (await deriveWorkerKey(secret, offset) === candidate) return true;
  }
  return false;
}

// --- Helpers ---

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
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(privateKey),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(user));
  return hexEncode(new Uint8Array(sig));
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
