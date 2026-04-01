import type { IncomingMessage } from "node:http";
import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousFastifyOptions extends ObfiousConfig {
    creds: ObfiousCreds;
    getUser?: (req: IncomingMessage) => string | undefined;
}
export declare function obfiousPlugin(fastify: any, options: ObfiousFastifyOptions): Promise<void>;
