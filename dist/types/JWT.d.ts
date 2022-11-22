export declare class JWT {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signage: string;
    private _serialized;
    static fromSerialized(serializedJWT: string): JWT;
    constructor(header?: Record<string, unknown>, payload?: Record<string, unknown>);
    sign(secret: string): void;
    get serialized(): string;
}
