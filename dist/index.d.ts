export interface ObfiousConfig {
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
