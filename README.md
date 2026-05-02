# @obfious/js

Authless device intelligence for JavaScript: Cloudflare Workers, Next.js, Express, Fastify, Lambda.

## Install

```bash
npm install @obfious/js
```

## Platforms

| Import | Platform |
|--------|----------|
| `@obfious/js` | Cloudflare Workers, Deno, Bun, any Web API runtime |
| `@obfious/js/nextjs` | Next.js (App Router middleware) |
| `@obfious/js/express` | Express / Connect |
| `@obfious/js/fastify` | Fastify |
| `@obfious/js/lambda` | AWS Lambda (API Gateway) |

## Quick start

```typescript
import { Obfious } from "@obfious/js";

const obfious = new Obfious({
  keyId: process.env.OBFIOUS_KEY_ID,
  secret: process.env.OBFIOUS_SECRET,
  includePaths: ["/api/"],
});

// In your request handler:
const result = await obfious.protect(request, userId);  // userId is optional
if (result.response) return result.response;
// result.deviceId is set when token is valid
// result.networkId is set when network headers were forwarded
// result.botScore (0-1) indicates bot likelihood

// Script tag for HTML <head>:
const tag = await obfious.scriptTag({ nonce: "abc123" });
// -> <script src="/?{shimKey}=1" nonce="abc123"></script>
//    <script src="/?{bootstrapKey}={value}" async fetchpriority="low" nonce="abc123"></script>
```

`scriptTag()` returns two tags: a synchronous fetch hook shim (~350 bytes) and the deferred bootstrap. The shim ensures requests issued during page load are queued correctly until the bootstrap activates.

`result.botScore` (0-1) is set when validation succeeds; `result.resyncHeaders` carries server-side resync metadata which the integrations apply to the outgoing response automatically.

### Next.js

```typescript
import { createObfiousMiddleware, applyObfiousHeaders } from "@obfious/js/nextjs";
import { NextResponse } from "next/server";

const obfious = createObfiousMiddleware({
  creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
  includePaths: ["/api/"],
});

export async function middleware(request: NextRequest) {
  const result = await obfious(request);
  if (result.response) return result.response;
  // Apply Obfious side-effect headers (e.g. resync) to the downstream response
  return applyObfiousHeaders(result, NextResponse.next());
}
```

`createObfiousMiddleware` returns a function that yields a `ProtectResult` (matching the core API). Use the helper `applyObfiousHeaders` from `@obfious/js/nextjs` to forward `resyncHeaders` onto the response. Express/Fastify/Lambda integrations do this automatically.

### Express

```typescript
import express from "express";
import { obfiousMiddleware } from "@obfious/js/express";

const app = express();
app.use(obfiousMiddleware({
  creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
  includePaths: ["/api/"],
}));
```

### Fastify

```typescript
import Fastify from "fastify";
import { obfiousPlugin } from "@obfious/js/fastify";

const app = Fastify();
app.register(obfiousPlugin, {
  creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
  includePaths: ["/api/"],
});
```

### Lambda

```typescript
import { obfiousHandler } from "@obfious/js/lambda";

export const handler = obfiousHandler({
  creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
  includePaths: ["/api/"],
}, async (event, context) => {
  return { statusCode: 200, body: JSON.stringify({ ok: true }), headers: {} };
});
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | string | `https://api.obfious.com` | API base URL |
| `scriptPath` | string | (time-rotating) | Override the auto-derived script URL |
| `includePaths` | string[] | (all) | Only guard these path prefixes (supports `"METHOD:/path"` shorthand) |
| `excludePaths` | string[] | (none) | Always pass through these prefixes (supports `"METHOD:/path"` shorthand) |
| `privateKey` | string | -- | HMAC key for user ID encryption. When set, the optional `user` argument passed to `protect()` is HMAC-signed before being sent to the API for device-to-user association. An integrity MAC is also computed so the server can verify the tag came from a legitimate proxy. |
| `getClientIp` | callback | (auto) | Custom client IP extraction |
| `getPlatformSignals` | callback | (CF default) | Custom platform signal headers |
| `jaHeaderName` | string | `x-cf-ja4` | Header to read JA4 TLS fingerprint from when not behind Cloudflare |

### `includePaths` / `excludePaths` shorthand

Entries are matched as segment-aware path prefixes. As of protocol v2.6, an entry may also be method-qualified by prefixing it with an HTTP method and a colon:

```typescript
includePaths: [
  "/api/",                  // any method under /api/
  "POST:/api/checkout",     // only POST /api/checkout (and sub-paths)
  "GET:/health",            // only GET /health
],
excludePaths: [
  "GET:/api/health",        // pass GET /api/health through, guard everything else
],
```

Rules:
- The colon must appear within the first 8 characters of the entry.
- The prefix must be one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` (case-insensitive; normalised to uppercase internally).
- Anything else is treated as a plain prefix. So `"foo:/bar"` matches the literal path `"foo:/bar"`, not the path `"/bar"` under method `FOO`.
- Plain entries (no method prefix) match any request method.
- Method-qualified entries match only when both the request method and the path prefix match.

`ProtectResult` includes `deviceId`, `networkId`, `botScore`, and `resyncHeaders`. `networkId` is populated when the API returns a network identity (requires Cloudflare Workers or a platform that supplies ASN/country via `request.cf`). The Express/Fastify/Lambda integrations apply `resyncHeaders` to the outgoing response automatically; in Next.js, use `applyObfiousHeaders` (see above).

Express and Fastify expose these as `req.obfiousDeviceId`, `req.obfiousNetworkId`, and `req.obfiousBotScore`. Lambda injects `x-obfious-device-id`, `x-obfious-network-id`, and `x-obfious-bot-score` into the event headers.

## CSP requirements

Obfious needs to compile WebAssembly and spawn a Web Worker from same-origin URLs. If your app sets an explicit `script-src` directive, you must include `'wasm-unsafe-eval'`:

```
script-src 'self' 'wasm-unsafe-eval';
worker-src 'self';
```

If you only have `default-src 'self'` with **no** explicit `script-src`, WASM compilation is implicitly allowed and no additional directives are needed. The `'wasm-unsafe-eval'` requirement only kicks in when `script-src` is explicitly set.

`worker-src` similarly falls back to `script-src` then `default-src`; only set it explicitly if your policy requires it.

## User association

Pass an authenticated user ID to `protect()` to associate the device with the user:

```typescript
// After your own auth middleware has set req.user:
const result = await obfious.protect(request, req.user?.id);
```

Requires `privateKey` to be set in the config. When present, the user ID is HMAC-signed with `privateKey` before being forwarded; the raw ID is never sent to the Obfious API. An integrity MAC (`HMAC-SHA256(secret, tokenHex + "." + encryptedUser)`) is included so the server can verify the tag was produced by a legitimate proxy. User association is silently skipped when `privateKey` is absent or `user` is not provided.

## Protocol version

This package implements the Obfious consumer protocol v2.7. The authoritative spec lives at `docs/consumer-protocol.md` (with version history in `docs/consumer-protocol-changelog.md`) in the main `obfious` repository.

## License

See LICENSE file.
