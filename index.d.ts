export type HashAlgorithm =
  | 'SHA-1' | 'SHA1' | 'sha1'
  | 'SHA-256' | 'SHA256' | 'sha256'
  | 'SHA-384' | 'SHA384' | 'sha384'
  | 'SHA-512' | 'SHA512' | 'sha512'

export interface CookieSignatureOptions {
  separator?: string
  hash?: HashAlgorithm
}

export function normalizeHashAlgo(hash: string): string | undefined
export function encoded(str: string): Uint8Array
export function ab2str(buf: ArrayBuffer): string
export function str2ab(str: string): ArrayBuffer
export function secretToHmacKey(
  secret: string | BufferSource,
  hash: string,
  crypto?: Crypto
): Promise<CryptoKey>

export class CookieSignature {
  static get(opts?: CookieSignatureOptions): CookieSignature
  constructor(opts?: CookieSignatureOptions)
  separator: string
  hash: string
  sign(valueToSign: string, secret: string | BufferSource): Promise<string>
  unsign(signedCookieValue: string, secret: string | BufferSource): Promise<string | false>
}

declare const defaultInstance: CookieSignature
export default defaultInstance
