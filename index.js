let _crypto
async function getWebCrypto () {
  if (_crypto) return _crypto
  if (globalThis.crypto?.subtle) {
    // console.log('Loaded globalThis.crypto')
    return (_crypto = globalThis.crypto) // Node 20, browser
  }
  if (globalThis.crypto?.webcrypto?.subtle) {
    // console.log('Loaded globalThis.crypto.webcrypto')
    return (_crypto = globalThis.crypto.webcrypto) // Node 15/16/18 (repl)
  }
  /*
  const x = await import('node:crypto')
  if (x.webcrypto) {
    // console.log('Loaded import(\'node:crypto\').webcrypto')
    return (_crypto = x.webcrypto) // Node 15/16/18 (non-repl)
  }
  */
  throw new Error('Your runtime does not provide a WebCrypto library.')
}

let _buffer
async function getBuffer () {
  if (_buffer) return _buffer
  if (globalThis.buffer?.btoa) {
    // console.log('Loaded atob/btoa from globalThis.buffer')
    return (_buffer = globalThis.buffer) // Node 15/16/18/20
  }
  if (globalThis.btoa) {
    // console.log('Loaded atob/btoa from globalThis')
    return (_buffer = globalThis) // browser
  }
  /*
  const x = await import('node:buffer')
  if (x.btoa) {
    // console.log('Loaded atob/btoa from import(\'node:buffer\')')
    return (_buffer = x)
  }
  */
  throw new Error('Your runtime does not provide an impl for atob/btoa.')
}

const HASH_DIGEST_NAMES = new Map([
  ['SHA-1', 'SHA-1'],
  ['SHA1', 'SHA-1'],
  ['sha1', 'SHA-1'],
  //
  ['SHA-256', 'SHA-256'],
  ['SHA256', 'SHA-256'],
  ['sha256', 'SHA-256'],
  //
  ['SHA-384', 'SHA-384'],
  ['SHA384', 'SHA-384'],
  ['sha384', 'SHA-384'],
  //
  ['SHA-512', 'SHA-512'],
  ['SHA512', 'SHA-512'],
  ['sha512', 'SHA-512']
])

export function normalizeHashAlgo (hash) {
  return HASH_DIGEST_NAMES.get(hash)
}

// use TextEncoder to convert UTF16 string to UTF8 encoded text as Uint8Array
export function encoded (str) {
  return new TextEncoder().encode(str)
}

// ArrayBuffer to string
export function ab2str (buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf))
}

// string to ArrayBuffer
export function str2ab (str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

// convert a secret string to a raw CryptoKey object (returns Promise)
export async function secretToHmacKey (secret, hash, crypto) {
  if (!crypto) crypto = await getWebCrypto()
  const encodedSecret = typeof secret === 'string' ? encoded(secret) : secret // try what was given
  return crypto.subtle.importKey('raw', encodedSecret, { name: 'HMAC', hash }, false, ['sign', 'verify'])
}

// named export if you want to customize settings
export class CookieSignature {
  static get (opts) {
    return new CookieSignature(opts)
  }

  constructor (opts) {
    this.separator = typeof opts?.separator === 'string' ? opts.separator : '.'
    this.hash = normalizeHashAlgo(opts?.hash) || 'SHA-256'
    // this.logErrors = typeof opts?.logErrors === 'boolean' ? opts.logErrors : false
  }

  async sign (valueToSign, secret) {
    // first make sure runtime supports webcrypto and atob/btoa
    const [crypto, buffer] = await Promise.all([getWebCrypto(), getBuffer()])

    // validate arguments
    if (typeof valueToSign !== 'string') throw new TypeError('Cookie value must be provided as a string.')
    if (secret == null) throw new TypeError('Secret key must be provided.')

    const hmacKey = await secretToHmacKey(secret, this.hash, crypto)
    const sigAsArrayBuffer = await crypto.subtle.sign('HMAC', hmacKey, encoded(valueToSign))
    const signature = buffer.btoa(ab2str(sigAsArrayBuffer))
    return valueToSign + this.separator + signature.replace(/=+$/, '')
  }

  async unsign (signedCookieValue, secret) {
    // first make sure runtime supports webcrypto and atob/btoa
    const [crypto, buffer] = await Promise.all([getWebCrypto(), getBuffer()])

    // validate arguments
    if (typeof signedCookieValue !== 'string') throw new TypeError('Signed cookie string must be provided.')
    if (secret == null) throw new TypeError('Secret key must be provided.')

    const lastIndexOfSep = signedCookieValue.lastIndexOf(this.separator)
    const unsignedValue = signedCookieValue.slice(0, lastIndexOfSep)
    const givenSignature = signedCookieValue.slice(lastIndexOfSep + this.separator.length)
    let binaryString
    try {
      binaryString = buffer.atob(givenSignature)
    } catch (e) {
      // if (this.logErrors) console.warn(`Unable to convert "${givenSignature}" to a binary string.`, e)
      return false
    }
    const hmacKey = await secretToHmacKey(secret, this.hash, crypto)
    const valid = await crypto.subtle.verify('HMAC', hmacKey, str2ab(binaryString), encoded(unsignedValue))
    return valid && unsignedValue
  }
}

// singleton using default settings
export default new CookieSignature()
