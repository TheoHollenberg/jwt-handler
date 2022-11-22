/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/ban-types */
import { Base64 } from 'js-base64';
import jsSHA from 'jssha';
var JWT = /** @class */ (function () {
    function JWT(header, payload) {
        if (header === void 0) { header = { alg: 'HS256', type: 'JWT' }; }
        if (payload === void 0) { payload = {}; }
        this.header = { alg: 'HS256', type: 'JWT' };
        this.payload = {};
        this.signage = '';
        this._serialized = '';
        this.header = header;
        this.payload = payload;
        this.signage = '';
    }
    JWT.fromSerialized = function (serializedJWT) {
        var elements = serializedJWT.split('.');
        if (elements.length !== 3)
            throw new Error('No JWT string');
        var newJwt = new JWT();
        newJwt.header = JSON.parse(Base64.decode(elements[0]));
        newJwt.payload = JSON.parse(Base64.decode(elements[1]));
        // eslint-disable-next-line prefer-destructuring
        newJwt.signage = elements[2];
        return newJwt;
    };
    JWT.prototype.sign = function (secret) {
        var header = this.header['alg'] || 'HS256';
        var isHmac = header.startsWith('H');
        var isSha = header.startsWith(isHmac ? 'HS' : 'S');
        var hasSecret = !!secret;
        if (isHmac && isSha && !hasSecret)
            throw new Error('Hmac signage needs a valid secret');
        var baseJwt = "".concat(Base64.encode(JSON.stringify(this.header)), ".").concat(Base64.encode(JSON.stringify(this.payload)));
        // eslint-disable-next-line new-cap
        var shaObj = new jsSHA('SHA-256', 'TEXT', {
            hmacKey: { value: secret, format: 'TEXT' },
        });
        shaObj.update(baseJwt);
        this.signage = Base64.encode(shaObj.getHash('HEX'), true);
        this._serialized = "".concat(this.header, ".").concat(this.payload, ".").concat(this.signage);
    };
    Object.defineProperty(JWT.prototype, "serialized", {
        get: function () {
            return this._serialized;
        },
        enumerable: false,
        configurable: true
    });
    return JWT;
}());
export { JWT };
