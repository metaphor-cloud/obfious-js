import type { IncomingMessage } from "node:http";
import { Obfious } from "./proxy";
import type { ObfiousConfig, ObfiousCreds, ProtectResult } from "./proxy";
import { toWebRequest } from "./node-adapter";

export type { ObfiousConfig, ObfiousCreds, ProtectResult };
export { Obfious };

export interface ObfiousFastifyOptions extends ObfiousConfig {
  creds: ObfiousCreds;
  getUser?: (req: IncomingMessage) => string | undefined;
}

/**
 * Fastify plugin for Obfious v2.1.
 *
 * ```ts
 * import Fastify from "fastify";
 * import { obfiousPlugin } from "@obfious/js/fastify-v2";
 *
 * const app = Fastify();
 * app.register(obfiousPlugin, {
 *   creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
 *   includePaths: ["/api/"],
 * });
 * ```
 */
export async function obfiousPlugin(fastify: any, options: ObfiousFastifyOptions): Promise<void> {
  const { creds, getUser, ...config } = options;

  const obfious = new Obfious({
    ...config,
    keyId: creds.keyId,
    secret: creds.secret,
    getClientIp: config.getClientIp ?? ((req: Request) =>
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || req.headers.get("x-real-ip")
      || "unknown"
    ),
    getPlatformSignals: config.getPlatformSignals ?? (() => ({})),
  });

  fastify.addHook("onRequest", async (request: any, reply: any) => {
    const webReq = toWebRequest(request.raw);
    const user = getUser?.(request.raw);
    const result = await obfious.protect(webReq, user);

    if (result.response) {
      const headers: Record<string, string> = {};
      result.response.headers.forEach((value: string, key: string) => { headers[key] = value; });
      const body = await result.response.text();
      reply.code(result.response.status).headers(headers).send(body);
      return;
    }

    if (result.deviceId) {
      request.obfiousDeviceId = result.deviceId;
    }
    if (result.botScore !== undefined) {
      request.obfiousBotScore = result.botScore;
    }

    if (result.resyncHeaders) {
      for (const [name, value] of Object.entries(result.resyncHeaders)) {
        reply.header(name, value);
      }
    }
  });
}
