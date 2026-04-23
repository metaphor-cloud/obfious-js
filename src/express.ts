import type { IncomingMessage, ServerResponse } from "node:http";
import { Obfious } from "./proxy";
import type { ObfiousConfig, ObfiousCreds, ProtectResult } from "./proxy";
import { toWebRequest, writeWebResponse } from "./node-adapter";

export type { ObfiousConfig, ObfiousCreds, ProtectResult };
export { Obfious };

export interface ObfiousExpressOptions extends ObfiousConfig {
  creds: ObfiousCreds;
  getUser?: (req: IncomingMessage) => string | undefined;
}

/**
 * Express/Connect middleware for Obfious v2.1.
 *
 * ```ts
 * import express from "express";
 * import { obfiousMiddleware } from "@obfious/js/express-v2";
 *
 * const app = express();
 * app.use(obfiousMiddleware({
 *   creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
 *   includePaths: ["/api/"],
 * }));
 * ```
 */
export function obfiousMiddleware(options: ObfiousExpressOptions) {
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

  return async (req: IncomingMessage, res: ServerResponse, next: (err?: any) => void) => {
    try {
      const webReq = toWebRequest(req);
      const user = getUser?.(req);
      const result = await obfious.protect(webReq, user);

      if (result.response) {
        await writeWebResponse(res, result.response);
        return;
      }

      if (result.deviceId) {
        (req as any).obfiousDeviceId = result.deviceId;
      }
      if (result.botScore !== undefined) {
        (req as any).obfiousBotScore = result.botScore;
      }

      if (result.resyncHeaders) {
        for (const [name, value] of Object.entries(result.resyncHeaders)) {
          res.setHeader(name, value);
        }
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}
