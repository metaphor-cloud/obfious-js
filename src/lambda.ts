import { Obfious } from "./proxy";
import type { ObfiousConfig, ObfiousCreds, ProtectResult } from "./proxy";

export type { ObfiousConfig, ObfiousCreds, ProtectResult };
export { Obfious };

export interface APIGatewayProxyEvent {
  httpMethod: string;
  path: string;
  headers: Record<string, string | undefined>;
  multiValueHeaders?: Record<string, string[] | undefined>;
  queryStringParameters?: Record<string, string | undefined> | null;
  body: string | null;
  isBase64Encoded: boolean;
  requestContext: { identity?: { sourceIp?: string }; [key: string]: any };
}

export interface APIGatewayProxyResult {
  statusCode: number;
  headers?: Record<string, string>;
  body: string;
  isBase64Encoded?: boolean;
}

export type LambdaHandler = (
  event: APIGatewayProxyEvent,
  context: any,
) => Promise<APIGatewayProxyResult>;

function eventToRequest(event: APIGatewayProxyEvent): Request {
  const proto = event.headers["x-forwarded-proto"] || event.headers["X-Forwarded-Proto"] || "https";
  const host = event.headers["host"] || event.headers["Host"] || "localhost";
  let url = `${proto}://${host}${event.path}`;
  if (event.queryStringParameters) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(event.queryStringParameters)) {
      if (v != null) params.set(k, v);
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }
  const headers = new Headers();
  for (const [key, value] of Object.entries(event.headers)) {
    if (value) headers.set(key, value);
  }
  const hasBody = event.httpMethod !== "GET" && event.httpMethod !== "HEAD" && event.body != null;
  const body = hasBody ? (event.isBase64Encoded ? atob(event.body!) : event.body) : null;
  return new Request(url, { method: event.httpMethod, headers, body });
}

async function responseToResult(response: Response): Promise<APIGatewayProxyResult> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => { headers[key] = value; });
  return { statusCode: response.status, headers, body: await response.text() };
}

export interface ObfiousLambdaOptions extends Omit<ObfiousConfig, "keyId" | "secret"> {
  creds: ObfiousCreds;
  getUser?: (event: APIGatewayProxyEvent) => string | undefined;
}

/**
 * Wrap a Lambda handler with Obfious protection.
 *
 * ```ts
 * import { obfiousHandler } from "@obfious/js/lambda-v2";
 *
 * export const handler = obfiousHandler({
 *   creds: { keyId: process.env.OBFIOUS_KEY_ID!, secret: process.env.OBFIOUS_SECRET! },
 *   includePaths: ["/api/"],
 * }, async (event) => {
 *   return { statusCode: 200, body: JSON.stringify({ ok: true }), headers: {} };
 * });
 * ```
 */
export function obfiousHandler(options: ObfiousLambdaOptions, handler: LambdaHandler): LambdaHandler {
  const { creds, getUser, ...config } = options;

  const obfious = new Obfious({
    ...config,
    keyId: creds.keyId,
    secret: creds.secret,
    getClientIp: config.getClientIp ?? ((req: Request) =>
      req.headers.get("x-lambda-source-ip")
      || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || "unknown"
    ),
    getPlatformSignals: config.getPlatformSignals ?? (() => ({})),
  });

  return async (event, context) => {
    const request = eventToRequest(event);
    const lambdaIp = event.requestContext?.identity?.sourceIp
      || event.headers["x-forwarded-for"]?.split(",")[0]?.trim() || "unknown";
    request.headers.set("x-lambda-source-ip", lambdaIp);

    const user = getUser?.(event);
    const result = await obfious.protect(request, user);

    if (result.response) return responseToResult(result.response);

    if (result.deviceId) {
      event.headers["x-obfious-device-id"] = String(result.deviceId);
    }
    if (result.networkId) {
      event.headers["x-obfious-network-id"] = String(result.networkId);
    }
    if (result.botScore !== undefined) {
      event.headers["x-obfious-bot-score"] = String(result.botScore);
    }

    const handlerResult = await handler(event, context);
    if (result.resyncHeaders) {
      handlerResult.headers = { ...handlerResult.headers, ...result.resyncHeaders };
    }
    return handlerResult;
  };
}
