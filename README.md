# cookie-signature-subtle

> Sign and unsign cookies using web standard SubtleCrypto (browser-compatible)

[![CI Status](https://github.com/nexdrew/cookie-signature-subtle/actions/workflows/ci.yml/badge.svg)](https://github.com/nexdrew/cookie-signature-subtle/actions/workflows/ci.yml)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-brightgreen.svg)](https://conventionalcommits.org)

This library makes it easy to sign response cookie values and authenticate request cookie values using a shared secret. Although the intent is to handle cookie values for your application, this library doesn't work directly with request or response headers, and it can be used for signing/authenticating any simple strings.

This is a rewrite of the original [`cookie-signature` package](https://www.npmjs.com/package/cookie-signature) that uses the [`SubtleCrypto`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) standard of the modern [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) instead of the [Node.js-specific `crypto` module](https://nodejs.org/dist/latest/docs/api/crypto.html), for better compatibility with runtimes like [Vercel's Edge Runtime](https://vercel.com/docs/functions/edge-functions/edge-runtime). It shares the same API contract as `cookie-signature` except that the methods are asynchronous (returning a `Promise`) instead of synchronous, due to the nature of the `SubtleCrypto` API.

This library is meant to be compatible with web standards and modern runtimes. Although it should be compatible with a browser environment/runtime, it is generally not a good idea to expose secrets used for generating digital signatures to code running on a client's browser.

See below for usage and examples.

## Install

```console
$ npm i cookie-signature-subtle
```

```js
// default export for standard use
import signature from 'cookie-signature-subtle'

const secret = 'not a good secret'

const signedValue = await signature.sign('cookievalue', secret)
// => 'cookievalue.XAn8/gvhqwlDLy7ibUMVNWlXpQetHJJFQ9cz6u9Oeeg'

const originalValue = await signature.unsign(signedValue, secret)
// => 'cookievalue'

const bogusValue = await signature.unsign('not valid', secret)
// => false

const bogusSecret = await signature.unsign(signedValue, 'another bad secret')
// => false
```

```js
// named export for customization
import { CookieSignature } from 'cookie-signature-subtle'

const signature = CookieSignature.get({ separator: '_', hash: 'SHA-512' })
const secret = 'not a good secret'

const signedValue = await signature.sign('cookievalue', secret)
// => 'cookievalue_/8OaZNevtP9If8FmWIbA6AWo9Tuowu/GXnYQ90VvzztyQzNCsLCBnRbVXIuqE3bUCahmlXhHN33zNAdWm55azw'

const originalValue = await signature.unsign(signedValue, secret)
// => 'cookievalue'

const bogusValue = await signature.unsign('not valid', secret)
// => false

const bogusSecret = await signature.unsign(signedValue, 'another bad secret')
// => false
```

## API

The default export is an instance of the `CookieSignature` class configured with default options that are compatible with the original `cookie-signature` package except that the methods of this library are async (return a `Promise`). Otherwise the API contract is the same as `cookie-signature`.

The main API methods are:

- `signature.sign(valueToSign, secret)`

    Sign the given string with a signature derived from the given secret.

    `valueToSign` must be a string; otherwise this method rejects (throws) with a `TypeError`.

    `secret` may be a string, `Buffer`, `TypedArray`, `CryptoKey`, or anything accepted by [`importKey`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey). It cannot be null or undefined; otherwise this method rejects (throws) with a `TypeError`.

    Returns a `Promise` that resolves to a string containing the given value concatenated with a separator (`'.'` by default) and the HMAC signature (a sha256 hash by default) encoded as base64 without any padding. The returned value can be provided to the `unsign` method with the same secret to validate its authenticity and be converted back to the original unsigned value.

    Example:

    ```js
    import signature from 'cookie-signature-subtle'

    const signedValue = await signature.sign('hello', 'not a good secret')
    // => 'hello.6J710tYHo2C2ka+uG9bw9xol/u3K+Is1FVaOyNlAiBE'
    ```

- `signature.unsign(signedCookieValue, secret)`

    Convert an authenticated/signed string value back into its original unsigned string value.

    `signedCookieValue` must be a string; otherwise this method rejects (throws) with a `TypeError`.

    `secret` may be a string, `Buffer`, `TypedArray`, `CryptoKey`, or anything accepted by [`importKey`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey). It cannot be null or undefined; otherwise this method rejects (throws) with a `TypeError`.

    Returns a `Promise` that resolves to either the unsigned string value (if authenticated) or the boolean value `false` (if not authenticated).

    Example:

    ```js
    import signature from 'cookie-signature-subtle'

    const originalValue = await signature.unsign('hello.6J710tYHo2C2ka+uG9bw9xol/u3K+Is1FVaOyNlAiBE', 'not a good secret')
    // => 'hello'

    const bogusValue = await signature.unsign('not valid', 'not a good secret')
    // => false
    ```

This module also exports the `CookieSignature` class as a named export if you'd like to customize the separator or hash algorithm used. You can construct your own signature instance using the constructor (i.e. `new CookieSignature(opts)`) or a static `get` convenience method (i.e. `CookieSignature.get(opts)`).

The options accepted when constructing a new instance are:

- `opts.separator` (string, default `'.'`): the string used to separate the unsigned value from the signature in the signed value

    Must be a string; otherwise the given option will be ignored and `'.'` will be used.

    Since the signature is always a base64-encoded string, make sure you use a separator that will never be part of the encoded signature (i.e. don't use a-z, A-Z, 0-9, `'+'`, or `'/'`).

    Example:

    ```js
    import { CookieSignature } from 'cookie-signature-subtle'
    const signature = CookieSignature.get({ separator: '_' })

    const signedValue = await signature.sign('hello', 'not a good secret')
    // => 'hello_6J710tYHo2C2ka+uG9bw9xol/u3K+Is1FVaOyNlAiBE'

    const originalValue = await signature.unsign(signedValue, 'not a good secret')
    // => 'hello'
    ```

- `opts.hash` (string, default `'SHA-256'`): the hashing algorithm to use when generating the signature

    Per the `SubtleCrypto` API, accepts values `'SHA-1'`, `'SHA-256'`, `'SHA-384'`, or `'SHA-512'`. If an unknown value is given, it will be ignored and `'SHA-256'` will be used.

    Example:

    ```js
    import { CookieSignature } from 'cookie-signature-subtle'
    const signature = CookieSignature.get({ hash: 'SHA-384' })

    const signedValue = await signature.sign('hello', 'not a good secret')
    // => 'hello.6J0vmMamuPKikY6ufK/uE6oqE75/7GwjtixxVss8MBGtLv07L9UuiAFjHhU7wPyA'

    const originalValue = await signature.unsign(signedValue, 'not a good secret')
    // => 'hello'
    ```

## License

ISC © Andrew Goode
