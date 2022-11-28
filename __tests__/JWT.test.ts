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
    'eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.e30.YjY0ZTJmMzk3ZmNhMTgyNGE3OWRiMDQ0MzM3MjY4ODU5YzM2MmNkZDY0NThmZDA4M2QxNGU4ZjNhNTM2OGJhZg'
  )
})
