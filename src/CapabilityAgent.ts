/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import type {
  ISigner,
  IVerificationKeyPair2020
} from '@interop/data-integrity-core'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

const { subtle } = globalThis.crypto

/**
 * The public + private Ed25519 verification key descriptor backing a
 * CapabilityAgent's invocation signer: the shared `IVerificationKeyPair2020`
 * shape, with the fields this export guarantees made required.
 */
export type VerificationKeyDescriptor = IVerificationKeyPair2020 &
  Required<
    Pick<IVerificationKeyPair2020, 'type' | 'controller' | 'publicKeyMultibase'>
  >

export class CapabilityAgent {
  handle: string
  id: string
  signer: ISigner
  // Underlying Ed25519 key pair used for invocation signing. Read it through
  // getVerificationKeyPair() rather than touching this field directly.
  protected _keyPair: Ed25519VerificationKey

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
   * @param {object} options.signer - An API with an `id` property and a
   *   `sign` function.
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
    signer: ISigner
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
   * @returns {object} An API with an `id` property and a `sign` function.
   */
  getSigner(): ISigner {
    return this.signer
  }

  /**
   * Returns the Ed25519 verification key pair backing this agent's invocation
   * signer, as a plain descriptor with `controller` set to this agent's
   * did:key id. Exposed so callers can derive related keys -- e.g. the X25519
   * key agreement key (the Montgomery form of this signing key) used for
   * encrypted storage -- without reaching into private internals.
   *
   * @returns {VerificationKeyDescriptor} The signing key pair. Includes the
   *   private key material; treat the result as sensitive.
   */
  getVerificationKeyPair(): VerificationKeyDescriptor {
    const { type, publicKeyMultibase } = this._keyPair
    if (!type || !publicKeyMultibase) {
      throw new Error(
        'CapabilityAgent is missing Ed25519 key material; cannot export ' +
          'verification key pair.'
      )
    }
    // defer to the key class's canonical exporter so the descriptor tracks
    // its export format
    return {
      ...this._keyPair.toVerificationKey2020({
        publicKey: true,
        privateKey: true
      }),
      type,
      publicKeyMultibase,
      controller: this.id
    }
  }

  /**
   * Deterministically generates a CapabilityAgent from a secret, a semantic
   * handle to uniquely identify the secret, and a key name. The same secret
   * can be used to generate multiple keys by using different key names.
   *
   * Equivalent to `seedFromSecret()` followed by `fromSeed()`; use those
   * directly to capture the intermediate seed (e.g. to store it wrapped so
   * the same agent can later be reconstituted without the secret).
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
    const seed = await CapabilityAgent.seedFromSecret({ secret, handle })
    return CapabilityAgent.fromSeed({ seed, handle, keyName })
  }

  /**
   * Computes the deterministic seed `fromSecret()` derives its keys from: the
   * SHA-256 hash of the secret salted with the handle. Exposed so callers can
   * persist the seed (suitably encrypted) and later reconstitute the same
   * agent via `fromSeed()` without the original secret.
   *
   * @param {object} options - The options to use.
   * @param {string|Uint8Array} [options.secret] - A secret to use as input
   *   when generating the key, e.g., a bcrypt hash of a password.
   * @param {string} options.handle - A semantic identifier for the secret
   *   that is mixed with it like a salt to produce the seed.
   *
   * @returns {Promise<Uint8Array>} The 32-byte seed.
   */
  static async seedFromSecret({
    secret,
    handle
  }: {
    secret?: string | Uint8Array
    handle: string
  }): Promise<Uint8Array> {
    if (typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.')
    }
    // do not pre-encode a string secret here; `_computeSaltedHash` needs the
    // original type to hash binary secrets without a lossy UTF-8 round-trip
    if (typeof secret !== 'string' && !(secret instanceof Uint8Array)) {
      throw new TypeError('"secret" must be a Uint8Array or a string.')
    }

    // compute salted SHA-256 hash as the seed for the key
    return _computeSaltedHash({ secret, salt: handle })
  }

  /**
   * Deterministically generates a CapabilityAgent from an already-derived
   * seed (see `seedFromSecret()`), skipping the secret-hashing step: the same
   * seed and key name always reconstitute the same agent, so a stored seed
   * stands in for the original secret. Note the seed enters the derivation
   * as-is -- passing it to `fromSecret()` instead would hash it again and
   * yield a different agent.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.seed - The seed to derive the key from, as
   *   produced by `seedFromSecret()`.
   * @param {string} options.handle - The semantic identifier for the secret
   *   the seed was derived from (identifies the agent; it does not affect
   *   the key, which the seed already encodes).
   * @param {string} [options.keyName='default'] - An optional name to use to
   *   generate the key.
   *
   * @returns {Promise<CapabilityAgent>} The new CapabilityAgent instance.
   */
  static async fromSeed({
    seed,
    handle,
    keyName = 'default'
  }: {
    seed: Uint8Array
    handle: string
    keyName?: string
  }): Promise<CapabilityAgent> {
    if (typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.')
    }
    if (!(seed instanceof Uint8Array) || seed.length === 0) {
      throw new TypeError('"seed" must be a non-empty Uint8Array.')
    }

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
}): Promise<{ signer: ISigner; keyPair: Ed25519VerificationKey }> {
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

  // create signer for the key (includes the key's `id`, set above)
  const signer = keyPair.signer()
  return { signer, keyPair }
}
