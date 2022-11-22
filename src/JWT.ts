/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/ban-types */
import { Base64 } from 'js-base64'
import jsSHA from 'jssha'

export class JWT {
  header: Record<string, unknown> = { alg: 'HS256', type: 'JWT' }
  payload: Record<string, unknown> = {}
  signage = ''
  private _serialized = ''

  static fromSerialized(serializedJWT: string): JWT {
    const elements: Array<string> = serializedJWT.split('.')
    if (elements.length !== 3) throw new Error('No JWT string')
    const newJwt = new JWT()
    newJwt.header = JSON.parse(Base64.decode(elements[0]))
    newJwt.payload = JSON.parse(Base64.decode(elements[1]))
    // eslint-disable-next-line prefer-destructuring
    newJwt.signage = elements[2]
    return newJwt
  }

  constructor(
    header: Record<string, unknown> = { alg: 'HS256', type: 'JWT' },
    payload: Record<string, unknown> = {}
  ) {
    this.header = header
    this.payload = payload
    this.signage = ''
  }

  public sign(secret: string): void {
    const header = (this.header['alg'] as string) || 'HS256'
    const isHmac: boolean = header.startsWith('H')
    const isSha: boolean = header.startsWith(isHmac ? 'HS' : 'S')
    const hasSecret = !!secret

    if (isHmac && isSha && !hasSecret)
      throw new Error('Hmac signage needs a valid secret')

    const baseJwt = `${Base64.encode(
      JSON.stringify(this.header)
    )}.${Base64.encode(JSON.stringify(this.payload))}`

    // eslint-disable-next-line new-cap
    const shaObj = new jsSHA('SHA-256', 'TEXT', {
      hmacKey: { value: secret, format: 'TEXT' },
    })
    shaObj.update(baseJwt)

    this.signage = Base64.encode(shaObj.getHash('HEX'), true)
    this._serialized = `${this.header}.${this.payload}.${this.signage}`
  }

  get serialized(): string {
    return this._serialized;
  }

}
