# @obfious/js

Authless device intelligence for JavaScript — Cloudflare Workers, Next.js, Express, Fastify, Lambda.

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
const result = await obfious.protect(request);
if (result.response) return result.response;
// result.deviceId is set when token is valid
// result.botScore (0-1) indicates bot likelihood

// Script tag for HTML <head>:
const tag = await obfious.scriptTag({ nonce: "abc123" });
// -> <script src="/?{shimKey}=1" nonce="abc123"></script>
//    <script src="/?{bootstrapKey}={value}" async fetchpriority="low" nonce="abc123"></script>
```

`scriptTag()` returns two tags — a synchronous fetch hook shim (~350 bytes) and the deferred bootstrap. The shim ensures requests issued during page load are queued correctly until the bootstrap activates.

`result.botScore` (0–1) is set when validation succeeds; `result.resyncHeaders` carries server-side resync metadata which the integrations apply to the outgoing response automatically.

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

`createObfiousMiddleware` returns a function that yields a `ProtectResult` (matching the core API). Use the helper `applyObfiousHeaders` from `@obfious/js/nextjs` to forward `resyncHeaders` onto the response — Express/Fastify/Lambda integrations do this automatically.

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
| `includePaths` | string[] | (all) | Only guard these path prefixes |
| `excludePaths` | string[] | (none) | Always pass through these prefixes |
| `privateKey` | string | -- | HMAC key for user ID encryption |
| `getClientIp` | callback | (auto) | Custom client IP extraction |
| `getPlatformSignals` | callback | (CF default) | Custom platform signal headers |
| `jaHeaderName` | string | `x-cf-ja4` | Header to read JA4 TLS fingerprint from when not behind Cloudflare |

`ProtectResult` includes `deviceId`, `botScore`, and `resyncHeaders`. The Express/Fastify/Lambda integrations apply `resyncHeaders` to the outgoing response automatically; in Next.js, use `applyObfiousHeaders` (see above).

## CSP requirements

Obfious needs to compile WebAssembly and spawn a Web Worker from same-origin URLs. If your app sets an explicit `script-src` directive, you must include `'wasm-unsafe-eval'`:

```
script-src 'self' 'wasm-unsafe-eval';
worker-src 'self';
```

If you only have `default-src 'self'` with **no** explicit `script-src`, WASM compilation is implicitly allowed and no additional directives are needed. The `'wasm-unsafe-eval'` requirement only kicks in when `script-src` is explicitly set.

`worker-src` similarly falls back to `script-src` then `default-src` — only set it explicitly if your policy requires it.

## License

See LICENSE file.
