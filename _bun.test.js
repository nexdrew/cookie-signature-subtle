import { test, expect } from 'bun:test'
import cs, { CookieSignature } from './index.js'

test('singleton.sign(valueToSign, secret) should sign the cookie', async () => {
  const signed = await cs.sign('hello', 'tobiiscool')
  expect(signed).toBe('hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI')

  const signed2 = await cs.sign('hello', 'luna')
  expect(signed2).not.toBe('hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI')
})

test('singleton.sign(valueToSign, secret) should accept appropriately non-string secrets', async () => {
  const signed = await cs.sign('hello', Buffer.from('A0ABBC0C', 'hex'))
  expect(signed).toBe('hello.hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to')

  expect(cs.sign('unsupported', new Date())).rejects.toThrow(TypeError)
})

test('singleton.unsign(signedCookieValue, secret) should unsign the cookie', async () => {
  const signed = await cs.sign('hello', 'tobiiscool')

  const unsigned = await cs.unsign(signed, 'tobiiscool')
  expect(unsigned).toBe('hello')

  const unsigned2 = await cs.unsign(signed, 'luna')
  expect(unsigned2).toBe(false)
})

test('singleton.unsign(signedCookieValue, secret) should reject malformed cookies', async () => {
  const secret = 'actual sekrit password'

  const unsigned = await cs.unsign('fake unsigned data', secret)
  expect(unsigned).toBe(false)

  const signed = await cs.sign('real data', secret)
  const unsigned2 = await cs.unsign('garbage' + signed, secret)
  expect(unsigned2).toBe(false)

  const unsigned3 = await cs.unsign('garbage.' + signed, secret)
  expect(unsigned3).toBe(false)

  const unsigned4 = await cs.unsign(signed + '.garbage', secret)
  expect(unsigned4).toBe(false)

  const unsigned5 = await cs.unsign(signed + 'garbage', secret)
  expect(unsigned5).toBe(false)
})

test('singleton.unsign(signedCookieValue, secret) should accept non-string secrets', async () => {
  const key = Uint8Array.from([0xA0, 0xAB, 0xBC, 0x0C])
  const unsignedValue = await cs.unsign('hello.hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to', key)
  expect(unsignedValue).toBe('hello')
})

test('custom.sign(valueToSign, secret) should sign the cookie', async () => {
  const custom = CookieSignature.get({ separator: '_', hash: 'sha384' })

  const signed = await custom.sign('hello', 'tobiiscool')
  expect(signed).toBe('hello_RJljN3thz3FGathvIVhUDu5T2fohzb9YVHfOB+dId9Y+JHYcQlIhSUP6WioF2sFr')

  const signed2 = await custom.sign('hello', 'luna')
  expect(signed2).not.toBe('hello_RJljN3thz3FGathvIVhUDu5T2fohzb9YVHfOB+dId9Y+JHYcQlIhSUP6WioF2sFr')
})

test('custom.sign(valueToSign, secret) should accept appropriately non-string secrets', async () => {
  const custom = new CookieSignature({ separator: '-', hash: 'SHA512' })

  const signed = await custom.sign('hello', Buffer.from('A0ABBC0C', 'hex'))
  expect(signed).toBe('hello-TMqblNnVoVmU9HCgoYZ32oOOQHXvSY3MAHsmFaH32gl/X7uUF8pvfkj4m0wbyfGp9Sy7rmDU8C2JlSiWxxpjwA')

  expect(custom.sign('unsupported', new Date())).rejects.toThrow(TypeError)
})

test('custom.unsign(signedCookieValue, secret) should unsign the cookie', async () => {
  const custom = CookieSignature.get({ separator: '**', hash: 'SHA-1' })
  const signed = await custom.sign('hello', 'tobiiscool')

  const unsigned = await custom.unsign(signed, 'tobiiscool')
  expect(unsigned).toBe('hello')

  const unsigned2 = await custom.unsign(signed, 'luna')
  expect(unsigned2).toBe(false)
})

test('custom.unsign(signedCookieValue, secret) should reject malformed cookies', async () => {
  const custom = new CookieSignature({ separator: '¯\\_(ツ)_/¯', hash: 'sha256' })
  const secret = 'actual sekrit password'

  const unsigned = await custom.unsign('fake unsigned data', secret)
  expect(unsigned).toBe(false)

  const signed = await custom.sign('real data', secret)
  const unsigned2 = await custom.unsign('garbage' + signed, secret)
  expect(unsigned2).toBe(false)

  const unsigned3 = await custom.unsign('garbage.' + signed, secret)
  expect(unsigned3).toBe(false)

  const unsigned4 = await custom.unsign(signed + '.garbage', secret)
  expect(unsigned4).toBe(false)

  const unsigned5 = await custom.unsign(signed + 'garbage', secret)
  expect(unsigned5).toBe(false)
})

test('custom.unsign(signedCookieValue, secret) should accept non-string secrets', async () => {
  const custom = CookieSignature.get({ separator: '**', hash: 'SHA-256' })
  const key = Uint8Array.from([0xA0, 0xAB, 0xBC, 0x0C])
  const unsignedValue = await custom.unsign('hello**hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to', key)
  expect(unsignedValue).toBe('hello')
})

test('sign(valueToSign, secret) requires valueToSign to be a string', async () => {
  expect(cs.sign(123, 'secret')).rejects.toThrow(TypeError)
  expect(cs.sign(123, 'secret')).rejects.toThrow('Cookie value must be provided as a string.')
})

test('sign(valueToSign, secret) requires secret to be defined', async () => {
  expect(cs.sign('hello')).rejects.toThrow(TypeError)
  expect(cs.sign('hello')).rejects.toThrow('Secret key must be provided.')

  expect(cs.sign('hello', null)).rejects.toThrow(TypeError)
  expect(cs.sign('hello', null)).rejects.toThrow('Secret key must be provided.')
})

test('unsign(signedCookieValue, secret) requires signedCookieValue to be a string', async () => {
  expect(cs.unsign(123, 'secret')).rejects.toThrow(TypeError)
  expect(cs.unsign(123, 'secret')).rejects.toThrow('Signed cookie string must be provided.')
})

test('unsign(signedCookieValue, secret) requires secret to be defined', async () => {
  expect(cs.unsign('hello')).rejects.toThrow(TypeError)
  expect(cs.unsign('hello')).rejects.toThrow('Secret key must be provided.')

  expect(cs.unsign('hello', null)).rejects.toThrow(TypeError)
  expect(cs.unsign('hello', null)).rejects.toThrow('Secret key must be provided.')
})

test('custom ignores invalid hash option', () => {
  const custom = new CookieSignature({ hash: 'x' })
  expect(custom.hash).toBe('SHA-256')
})

test('custom ignores non-string separator option', () => {
  const custom = new CookieSignature({ separator: new Date() })
  expect(custom.separator).toBe('.')
})
