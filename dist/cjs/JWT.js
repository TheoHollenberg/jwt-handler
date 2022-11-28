"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT = void 0;
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/ban-types */
const js_base64_1 = require("js-base64");
const jssha_1 = __importDefault(require("jssha"));
class JWT {
    static fromSerialized(serializedJWT) {
        const elements = serializedJWT.split('.');
        if (elements.length !== 3)
            throw new Error('No JWT string');
        const newJwt = new JWT();
        newJwt.header = JSON.parse(js_base64_1.Base64.decode(elements[0]));
        newJwt.payload = JSON.parse(js_base64_1.Base64.decode(elements[1]));
        // eslint-disable-next-line prefer-destructuring
        newJwt.signage = elements[2];
        return newJwt;
    }
    constructor(header = { alg: 'HS256', type: 'JWT' }, payload = {}) {
        this.header = { alg: 'HS256', type: 'JWT' };
        this.payload = {};
        this.signage = '';
        this._serialized = '';
        this.header = header;
        this.payload = payload;
        this.signage = '';
    }
    sign(secret) {
        const header = this.header['alg'] || 'HS256';
        const isHmac = header.startsWith('H');
        const isSha = header.startsWith(isHmac ? 'HS' : 'S');
        const hasSecret = !!secret;
        if (isHmac && isSha && !hasSecret)
            throw new Error('Hmac signage needs a valid secret');
        const baseJwt = `${js_base64_1.Base64.encode(JSON.stringify(this.header))}.${js_base64_1.Base64.encode(JSON.stringify(this.payload))}`;
        // eslint-disable-next-line new-cap
        const shaObj = new jssha_1.default('SHA-256', 'TEXT', {
            hmacKey: { value: secret, format: 'TEXT' },
        });
        shaObj.update(baseJwt);
        this.signage = js_base64_1.Base64.encode(shaObj.getHash('HEX'), true);
        this._serialized = `${this.header}.${this.payload}.${this.signage}`;
    }
    get serialized() {
        return this._serialized;
    }
}
exports.JWT = JWT;
