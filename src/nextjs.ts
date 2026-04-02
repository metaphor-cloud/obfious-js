import { Obfious } from "./proxy";
import type { ObfiousConfig, ProtectResult } from "./proxy";

export type { ObfiousConfig, ProtectResult };
export { Obfious };

/**
 * Create middleware for Next.js App Router (edge runtime).
 *
 * ```ts
 * import { createObfiousMiddleware } from "@obfious/js/nextjs";
 *
 * const obfious = createObfiousMiddleware({
 *   creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
 *   includePaths: ["/api/"],
 * });
 *
 * export async function middleware(request: NextRequest) {
 *   const response = await obfious(request);
 *   if (response) return response;
 *   return NextResponse.next();
 * }
 * ```
 */
export function createObfiousMiddleware(config: ObfiousConfig) {
  const obfious = new Obfious({
    ...config,
    getClientIp: config.getClientIp ?? ((req: Request) =>
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || req.headers.get("x-real-ip")
      || "unknown"
    ),
  });

  return async (request: Request): Promise<Response | null> => {
    const result = await obfious.protect(request);
    return result.response;
  };
}

export async function obfiousScriptTag(obfious: Obfious, nonce?: string): Promise<string> {
  return obfious.scriptTag({ nonce });
}
