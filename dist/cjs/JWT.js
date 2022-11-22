"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT = void 0;
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/ban-types */
var js_base64_1 = require("js-base64");
var jssha_1 = __importDefault(require("jssha"));
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
        newJwt.header = JSON.parse(js_base64_1.Base64.decode(elements[0]));
        newJwt.payload = JSON.parse(js_base64_1.Base64.decode(elements[1]));
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
        var baseJwt = "".concat(js_base64_1.Base64.encode(JSON.stringify(this.header)), ".").concat(js_base64_1.Base64.encode(JSON.stringify(this.payload)));
        // eslint-disable-next-line new-cap
        var shaObj = new jssha_1.default('SHA-256', 'TEXT', {
            hmacKey: { value: secret, format: 'TEXT' },
        });
        shaObj.update(baseJwt);
        this.signage = js_base64_1.Base64.encode(shaObj.getHash('HEX'), true);
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
exports.JWT = JWT;
