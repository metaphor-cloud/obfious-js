import type { IncomingMessage, ServerResponse } from "node:http";
import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousExpressOptions extends ObfiousConfig {
    creds: ObfiousCreds;
    getUser?: (req: IncomingMessage) => string | undefined;
}
export declare function obfiousMiddleware(options: ObfiousExpressOptions): (req: IncomingMessage, res: ServerResponse, next: (err?: any) => void) => Promise<void>;
