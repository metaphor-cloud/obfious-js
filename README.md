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
  includePaths: ["/api/"],
});

const creds = { keyId: process.env.OBFIOUS_KEY_ID, secret: process.env.OBFIOUS_SECRET };

// In your request handler:
const result = await obfious.protect(request, creds);
if (result.response) return result.response;
// result.deviceId is set when token is valid

// Script tag for HTML <head>:
const tag = await obfious.scriptTag({ nonce: "abc123" });
// -> <script src="/?a3f7c9d4e5=xR7kM2pQ" nonce="abc123"></script>
```

### Next.js

```typescript
import { createObfiousMiddleware } from "@obfious/js/nextjs";
import { NextResponse } from "next/server";

const obfious = createObfiousMiddleware({
  creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
  includePaths: ["/api/"],
});

export async function middleware(request: NextRequest) {
  const response = await obfious(request);
  if (response) return response;
  return NextResponse.next();
}
```

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

## CSP requirements

```
script-src 'self' 'wasm-unsafe-eval';
worker-src 'self';
connect-src 'self';
```

## License

See LICENSE file.
