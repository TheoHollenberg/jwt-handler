import { Base64 } from 'js-base64'
import jsSHA from 'jssha'
import { JWT } from '../src/index'

const SECRET = 'This is a secret!'

test('Create JWT', () => {
  const emptyObject = {}
  const jwt = new JWT()
  expect(jwt.header.alg).toBe('HS256')
  expect(jwt.payload).toEqual(emptyObject)
  expect(jwt.signage).toBe('')
  expect(jwt.isExpired).toBe(true)
})

test('Create Expiring JWT', () => {
  const emptyObject = {}
  const jwt = new JWT()
  jwt.expiresIn = 5
  expect(jwt.header.alg).toBe('HS256')
  expect(jwt.payload).not.toEqual(emptyObject)
  expect(jwt.signage).toBe('')
  expect(jwt.isExpired).toBe(false)
})

test('Sign JWT', () => {
  const jwt = new JWT()
  jwt.sign(SECRET)
  expect(jwt.signage).not.toBe('')
  expect(jwt.serialized).toEqual(
    'eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.e30.tk4vOX/KGCSnnbBEM3JohZw2LN1kWP0IPRTo86U2i68'
  )
})

test('Sign JWT with expiration', () => {
  const userName = 'p.test@meijers.nl'
  const secret = '*PdAehx46RvX2p7VhCs2_xE6hhc8ChTp8NWKvF-s'
  const jwt = new JWT()
  jwt.payload = { userName }
  jwt.expiresIn = 10
  jwt.sign(secret)
  console.log(jwt.serialized)
  expect(jwt.signage).not.toBe('')
})
