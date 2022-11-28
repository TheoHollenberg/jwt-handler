/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/ban-types */
import { Base64 } from 'js-base64';
import jsSHA from 'jssha';
export class JWT {
    static fromSerialized(serializedJWT) {
        const elements = serializedJWT.split('.');
        if (elements.length !== 3)
            throw new Error('No JWT string');
        const newJwt = new JWT();
        newJwt.header = JSON.parse(Base64.decode(elements[0]));
        newJwt.payload = JSON.parse(Base64.decode(elements[1]));
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
        const baseJwt = `${Base64.encode(JSON.stringify(this.header), true)}.${Base64.encode(JSON.stringify(this.payload), true)}`;
        // eslint-disable-next-line new-cap
        const shaObj = new jsSHA('SHA-256', 'TEXT', {
            hmacKey: { value: secret, format: 'TEXT' },
        });
        shaObj.update(baseJwt);
        this.signage = Base64.encode(shaObj.getHash('HEX'), true);
        this._serialized = `${baseJwt}.${this.signage}`;
    }
    set expiresIn(_expiresIn) {
        this.payload['exp'] = Date.now() + 1000 * _expiresIn;
    }
    get isExpired() {
        return (this.payload['exp'] || 0) < Date.now() ? true : false;
    }
    get serialized() {
        return this._serialized;
    }
}
