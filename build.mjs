#!/usr/bin/env node
import { build } from "esbuild";
import { writeFileSync, mkdirSync } from "fs";

mkdirSync("dist", { recursive: true });

const entries = {
  index: { platform: "neutral", external: [] },
  nextjs: { platform: "neutral", external: ["next", "next/*"] },
  express: { platform: "node", external: ["node:http", "node:stream"] },
  fastify: { platform: "node", external: ["node:http", "node:stream", "fastify"] },
  lambda: { platform: "node", external: [] },
};

for (const [name, opts] of Object.entries(entries)) {
  const result = await build({
    entryPoints: [`src/${name}.ts`],
    bundle: true,
    format: "esm",
    platform: opts.platform,
    target: "es2022",
    minify: true,
    write: false,
    treeShaking: true,
    legalComments: "none",
    external: opts.external,
  });

  writeFileSync(`dist/${name}.js`, result.outputFiles[0].text);
  console.log(`  ${name}.js (${result.outputFiles[0].text.length} bytes)`);
}

// --- Type declarations (v2.1) ---

writeFileSync("dist/index.d.ts", `export interface ObfiousConfig {
    apiUrl?: string;
    stableString?: string;
    scriptPath?: string;
    includePaths?: string[];
    excludePaths?: string[];
    privateKey?: string;
    getClientIp?: (request: Request) => string;
    getPlatformSignals?: (request: Request) => Record<string, string>;
}
export interface ObfiousCreds {
    keyId: string;
    secret: string;
}
export interface ProtectResult {
    response: Response | null;
    deviceId?: string;
}
export declare class Obfious {
    constructor(config?: ObfiousConfig);
    getScriptPath(): Promise<string>;
    scriptTag(opts?: { nonce?: string }): Promise<string>;
    protect(request: Request, creds?: ObfiousCreds, user?: string): Promise<ProtectResult>;
}
`);

writeFileSync("dist/nextjs.d.ts", `import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousMiddlewareConfig extends ObfiousConfig {
    creds: ObfiousCreds;
}
export declare function createObfiousMiddleware(config: ObfiousMiddlewareConfig): (request: Request) => Promise<Response | null>;
export declare function obfiousScriptTag(obfious: Obfious, nonce?: string): Promise<string>;
`);

writeFileSync("dist/express.d.ts", `import type { IncomingMessage, ServerResponse } from "node:http";
import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousExpressOptions extends ObfiousConfig {
    creds: ObfiousCreds;
    getUser?: (req: IncomingMessage) => string | undefined;
}
export declare function obfiousMiddleware(options: ObfiousExpressOptions): (req: IncomingMessage, res: ServerResponse, next: (err?: any) => void) => Promise<void>;
`);

writeFileSync("dist/fastify.d.ts", `import type { IncomingMessage } from "node:http";
import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousFastifyOptions extends ObfiousConfig {
    creds: ObfiousCreds;
    getUser?: (req: IncomingMessage) => string | undefined;
}
export declare function obfiousPlugin(fastify: any, options: ObfiousFastifyOptions): Promise<void>;
`);

writeFileSync("dist/lambda.d.ts", `import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
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
export type LambdaHandler = (event: APIGatewayProxyEvent, context: any) => Promise<APIGatewayProxyResult>;
export interface ObfiousLambdaOptions extends ObfiousConfig {
    creds: ObfiousCreds;
    getUser?: (event: APIGatewayProxyEvent) => string | undefined;
}
export declare function obfiousHandler(options: ObfiousLambdaOptions, handler: LambdaHandler): LambdaHandler;
`);

console.log("@obfious/js built successfully");
