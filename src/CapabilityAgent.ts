/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { InvocationSigner } from './types.js'

const { subtle } = globalThis.crypto

export class CapabilityAgent {
  handle: string
  id: string
  signer: InvocationSigner
  _keyPair: Ed25519VerificationKey

  /**
   * Creates a new instance of a CapabilityAgent that uses a KmsClient
   * instance that is, by default, bound to a particular keystore.
   *
   * A CapabilityAgent can provide an `invocationSigner` to a KmsClient
   * via its `getSigner` API, but a KmsClient instance is typically
   * used internally by other instances that can be created via
   * the CapabilityAgent API such as instances of the Kek and Hmac classes.
   *
   * The CapabilityAgent constructor should never be called directly. It
   * should always be created via a static method on the class. Use one of the
   * static methods in the examples to create a CapabilityAgent instance.
   *
   * @example
   * CapabilityAgent.fromSecret();
   * CapabilityAgent.fromBiometric();
   * CapabilityAgent.fromFido();
   *
   * @param {object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the key.
   * @param {object} options.signer - An API with an `id` property, a
   *   `type` property, and a `sign` function.
   * @typedef Ed25519VerificationKey
   * @param {Ed25519VerificationKey} options.keyPair - Underlying key pair.
   *
   * @returns {CapabilityAgent} The new instance.
   */
  constructor({
    handle,
    signer,
    keyPair
  }: {
    handle: string
    signer: InvocationSigner
    keyPair: Ed25519VerificationKey
  }) {
    this.handle = handle
    // signer is a did:key
    this.id = signer.id.split('#')[0] ?? signer.id
    this.signer = signer
    // reference to core key pair used for invocation signing
    this._keyPair = keyPair
  }

  /**
   * Gets a signer API, typically for signing capability invocation or
   * delegation proofs.
   *
   * @returns {object} An API with an `id` property, a `type` property, and a
   *   `sign` function.
   */
  getSigner(): InvocationSigner {
    return this.signer
  }

  /**
   * Deterministically generates a CapabilityAgent from a secret, a semantic
   * handle to uniquely identify the secret, and a key name. The same secret
   * can be used to generate multiple keys by using different key names.
   *
   * @param {object} options - The options to use.
   * @param {string|Uint8Array} [options.secret] - A secret to use as input
   *   when generating the key, e.g., a bcrypt hash of a password.
   * @param {string} options.handle - A semantic identifier for the secret
   *   that is mixed with it like a salt to produce a seed, and, if `cache` is
   *   true, will be used to identify the seed in the cache. A common use for
   *   this field is to use the account ID for a user in a system.
   * @param {string} [options.keyName='default'] - An optional name to use to
   *   generate the key.
   *
   * @returns {Promise<CapabilityAgent>} The new CapabilityAgent instance.
   */
  static async fromSecret({
    secret,
    handle,
    keyName = 'default'
  }: {
    secret?: string | Uint8Array
    handle: string
    keyName?: string
  }): Promise<CapabilityAgent> {
    if (typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.')
    }
    // do not pre-encode a string secret here; `_computeSaltedHash` needs the
    // original type to hash binary secrets without a lossy UTF-8 round-trip
    if (typeof secret !== 'string' && !(secret instanceof Uint8Array)) {
      throw new TypeError('"secret" must be a Uint8Array or a string.')
    }

    // compute salted SHA-256 hash as the seed for the key
    const seed = await _computeSaltedHash({ secret, salt: handle })
    const { signer, keyPair } = await _keyFromSeedAndName({ seed, keyName })
    return new CapabilityAgent({ handle, signer, keyPair })
  }

  static async fromBiometric(): Promise<CapabilityAgent> {
    throw new Error('Not implemented.')
  }

  static async fromFido(): Promise<CapabilityAgent> {
    throw new Error('Not implemented.')
  }
}

function _stringToUint8Array(data: string | Uint8Array): Uint8Array {
  if (typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data)
  }
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.')
  }
  return data
}

function _uint8ArrayToString(data: string | Uint8Array): string {
  if (typeof data === 'string') {
    // already a string
    return data
  }
  if (!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.')
  }
  // convert Uint8Array to string
  return new TextDecoder().decode(data)
}

async function _computeSaltedHash({
  secret,
  salt
}: {
  secret: string | Uint8Array
  salt: string | Uint8Array
}): Promise<Uint8Array> {
  // compute salted SHA-256 hash
  salt = _uint8ArrayToString(salt)
  let toHash: Uint8Array
  if (typeof secret === 'string') {
    // normalize the string exactly as the prior string -> bytes -> string path
    // did, then percent-encode, so the hashed bytes are unchanged for string
    // secrets
    secret = _uint8ArrayToString(_stringToUint8Array(secret))
    toHash = _stringToUint8Array(
      `${encodeURIComponent(salt)}:${encodeURIComponent(secret)}`
    )
  } else {
    // hash the raw secret bytes directly to avoid a lossy UTF-8 round-trip that
    // would collapse distinct binary secrets to the same seed; encodeURIComponent
    // percent-encodes ':' so the encoded salt prefix is an unambiguous separator
    const prefix = _stringToUint8Array(`${encodeURIComponent(salt)}:`)
    toHash = new Uint8Array(prefix.length + secret.length)
    toHash.set(prefix)
    toHash.set(secret, prefix.length)
  }
  const algorithm = { name: 'SHA-256' }
  return new Uint8Array(
    await subtle.digest(algorithm, toHash as Uint8Array<ArrayBuffer>)
  )
}

async function _keyFromSeedAndName({
  seed,
  keyName
}: {
  seed: Uint8Array
  keyName: string
}): Promise<{ signer: InvocationSigner; keyPair: Ed25519VerificationKey }> {
  const extractable = false
  const hmacKey = await subtle.importKey(
    'raw',
    seed as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: { name: 'SHA-256' } },
    extractable,
    ['sign']
  )
  const nameBuffer = _stringToUint8Array(keyName)
  const signature = new Uint8Array(
    await subtle.sign(
      hmacKey.algorithm,
      hmacKey,
      nameBuffer as Uint8Array<ArrayBuffer>
    )
  )
  // generate Ed25519 key from HMAC signature
  const keyPair = await Ed25519VerificationKey.generate({ seed: signature })

  // specify ID for key using fingerprint; must be set before `signer()`
  const fingerprint = keyPair.fingerprint()
  keyPair.id = `did:key:${fingerprint}#${fingerprint}`

  // create signer for the key
  const signer = keyPair.signer() as InvocationSigner
  signer.id = keyPair.id
  signer.type = keyPair.type
  return { signer, keyPair }
}
