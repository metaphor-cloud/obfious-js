import { Obfious, ObfiousConfig, ObfiousCreds, ProtectResult } from "@obfious/js";
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
