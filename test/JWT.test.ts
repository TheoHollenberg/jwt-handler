import { JWT } from '../src/index'

const SECRET = 'This is a secret!'

test('Create JWT', () => {
  const emptyObject = {}
  const jwt = new JWT()
  expect(jwt.header.alg).toBe('HS256')
  expect(jwt.payload).toEqual(emptyObject)
  expect(jwt.signage).toBe('')
})

test('Sign JWT', () => {
  const jwt = new JWT()
  jwt.sign(SECRET)
  expect(jwt.signage).not.toBe('')
})
