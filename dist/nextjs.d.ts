import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
export { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult };
export interface ObfiousMiddlewareConfig extends ObfiousConfig {
    creds: ObfiousCreds;
}
export declare function createObfiousMiddleware(config: ObfiousMiddlewareConfig): (request: Request) => Promise<Response | null>;
export declare function obfiousScriptTag(obfious: Obfious, nonce?: string): Promise<string>;
