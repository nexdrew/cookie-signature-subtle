import test from 'ava'
import cs, { CookieSignature } from './index.js'

test('singleton.sign(valueToSign, secret) should sign the cookie', async t => {
  const signed = await cs.sign('hello', 'tobiiscool')
  t.is(signed, 'hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI')

  const signed2 = await cs.sign('hello', 'luna')
  t.not(signed2, 'hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI')
})

test('singleton.sign(valueToSign, secret) should accept appropriately non-string secrets', async t => {
  const signed = await cs.sign('hello', Buffer.from('A0ABBC0C', 'hex'))
  t.is(signed, 'hello.hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to')

  await t.throwsAsync(
    cs.sign('unsupported', new Date()),
    {
      instanceOf: TypeError,
      // message: 'Failed to execute \'importKey\' on \'SubtleCrypto\': 2nd argument is not instance of ArrayBuffer, Buffer, TypedArray, or DataView.',
      code: 'ERR_INVALID_ARG_TYPE'
    }
  )
})

test('singleton.unsign(signedCookieValue, secret) should unsign the cookie', async t => {
  const signed = await cs.sign('hello', 'tobiiscool')

  const unsigned = await cs.unsign(signed, 'tobiiscool')
  t.is(unsigned, 'hello')

  const unsigned2 = await cs.unsign(signed, 'luna')
  t.is(unsigned2, false)
})

test('singleton.unsign(signedCookieValue, secret) should reject malformed cookies', async t => {
  const secret = 'actual sekrit password'

  const unsigned = await cs.unsign('fake unsigned data', secret)
  t.is(unsigned, false)

  const signed = await cs.sign('real data', secret)
  const unsigned2 = await cs.unsign('garbage' + signed, secret)
  t.is(unsigned2, false)

  const unsigned3 = await cs.unsign('garbage.' + signed, secret)
  t.is(unsigned3, false)

  const unsigned4 = await cs.unsign(signed + '.garbage', secret)
  t.is(unsigned4, false)

  const unsigned5 = await cs.unsign(signed + 'garbage', secret)
  t.is(unsigned5, false)
})

test('singleton.unsign(signedCookieValue, secret) should accept non-string secrets', async t => {
  const key = Uint8Array.from([0xA0, 0xAB, 0xBC, 0x0C])
  const unsignedValue = await cs.unsign('hello.hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to', key)
  t.is(unsignedValue, 'hello')
})

test('custom.sign(valueToSign, secret) should sign the cookie', async t => {
  const custom = CookieSignature.get({ separator: '_', hash: 'sha384' })

  const signed = await custom.sign('hello', 'tobiiscool')
  t.is(signed, 'hello_RJljN3thz3FGathvIVhUDu5T2fohzb9YVHfOB+dId9Y+JHYcQlIhSUP6WioF2sFr')

  const signed2 = await custom.sign('hello', 'luna')
  t.not(signed2, 'hello_RJljN3thz3FGathvIVhUDu5T2fohzb9YVHfOB+dId9Y+JHYcQlIhSUP6WioF2sFr')
})

test('custom.sign(valueToSign, secret) should accept appropriately non-string secrets', async t => {
  const custom = new CookieSignature({ separator: '-', hash: 'SHA512' })

  const signed = await custom.sign('hello', Buffer.from('A0ABBC0C', 'hex'))
  t.is(signed, 'hello-TMqblNnVoVmU9HCgoYZ32oOOQHXvSY3MAHsmFaH32gl/X7uUF8pvfkj4m0wbyfGp9Sy7rmDU8C2JlSiWxxpjwA')

  await t.throwsAsync(
    custom.sign('unsupported', new Date()),
    {
      instanceOf: TypeError,
      // message: 'Failed to execute \'importKey\' on \'SubtleCrypto\': 2nd argument is not instance of ArrayBuffer, Buffer, TypedArray, or DataView.',
      code: 'ERR_INVALID_ARG_TYPE'
    }
  )
})

test('custom.unsign(signedCookieValue, secret) should unsign the cookie', async t => {
  const custom = CookieSignature.get({ separator: '**', hash: 'SHA-1' })
  const signed = await custom.sign('hello', 'tobiiscool')

  const unsigned = await custom.unsign(signed, 'tobiiscool')
  t.is(unsigned, 'hello')

  const unsigned2 = await custom.unsign(signed, 'luna')
  t.is(unsigned2, false)
})

test('custom.unsign(signedCookieValue, secret) should reject malformed cookies', async t => {
  const custom = new CookieSignature({ separator: '¯\\_(ツ)_/¯', hash: 'sha256' })
  const secret = 'actual sekrit password'

  const unsigned = await custom.unsign('fake unsigned data', secret)
  t.is(unsigned, false)

  const signed = await custom.sign('real data', secret)
  const unsigned2 = await custom.unsign('garbage' + signed, secret)
  t.is(unsigned2, false)

  const unsigned3 = await custom.unsign('garbage.' + signed, secret)
  t.is(unsigned3, false)

  const unsigned4 = await custom.unsign(signed + '.garbage', secret)
  t.is(unsigned4, false)

  const unsigned5 = await custom.unsign(signed + 'garbage', secret)
  t.is(unsigned5, false)
})

test('custom.unsign(signedCookieValue, secret) should accept non-string secrets', async t => {
  const custom = CookieSignature.get({ separator: '**', hash: 'SHA-256' })
  const key = Uint8Array.from([0xA0, 0xAB, 0xBC, 0x0C])
  const unsignedValue = await custom.unsign('hello**hIvljrKw5oOZtHHSq5u+MlL27cgnPKX77y7F+x5r1to', key)
  t.is(unsignedValue, 'hello')
})

test('sign(valueToSign, secret) requires valueToSign to be a string', async t => {
  await t.throwsAsync(
    cs.sign(123, 'secret'),
    {
      instanceOf: TypeError,
      message: 'Cookie value must be provided as a string.'
    }
  )
})

test('sign(valueToSign, secret) requires secret to be defined', async t => {
  await t.throwsAsync(
    cs.sign('hello'),
    {
      instanceOf: TypeError,
      message: 'Secret key must be provided.'
    }
  )

  await t.throwsAsync(
    cs.sign('hello', null),
    {
      instanceOf: TypeError,
      message: 'Secret key must be provided.'
    }
  )
})

test('unsign(signedCookieValue, secret) requires signedCookieValue to be a string', async t => {
  await t.throwsAsync(
    cs.unsign(123, 'secret'),
    {
      instanceOf: TypeError,
      message: 'Signed cookie string must be provided.'
    }
  )
})

test('unsign(signedCookieValue, secret) requires secret to be defined', async t => {
  await t.throwsAsync(
    cs.unsign('hello'),
    {
      instanceOf: TypeError,
      message: 'Secret key must be provided.'
    }
  )

  await t.throwsAsync(
    cs.unsign('hello', null),
    {
      instanceOf: TypeError,
      message: 'Secret key must be provided.'
    }
  )
})

test('custom ignores invalid hash option', t => {
  const custom = new CookieSignature({ hash: 'x' })
  t.is(custom.hash, 'SHA-256')
})

test('custom ignores non-string separator option', t => {
  const custom = new CookieSignature({ separator: new Date() })
  t.is(custom.separator, '.')
})
