/**
 * Shared Node.js ↔ Web API conversion utilities.
 * Used by @obfious/express and @obfious/fastify.
 * Requires Node 18+ (Readable.toWeb, Web Streams).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

/**
 * Convert a Node.js IncomingMessage to a Web API Request.
 */
export function toWebRequest(req: IncomingMessage): Request {
  const proto = (req.headers["x-forwarded-proto"] as string) || "http";
  const host = req.headers.host || "localhost";
  const url = `${proto}://${host}${req.url}`;

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  }

  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  return new Request(url, {
    method: req.method,
    headers,
    body: hasBody ? Readable.toWeb(Readable.from(req)) as ReadableStream : null,
    // @ts-ignore — duplex required for streaming request bodies
    duplex: "half",
  });
}

/**
 * Write a Web API Response to a Node.js ServerResponse.
 */
export async function writeWebResponse(res: ServerResponse, webRes: Response): Promise<void> {
  const headers: Record<string, string> = {};
  webRes.headers.forEach((value, key) => { headers[key] = value; });
  res.writeHead(webRes.status, headers);

  if (webRes.body) {
    const reader = webRes.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
    } finally {
      reader.releaseLock();
    }
  }
  res.end();
}
