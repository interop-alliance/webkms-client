/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import { base64urlnopad } from '@scure/base'
import type { ISigner, IZcap } from '@interop/data-integrity-core'
import { assertNoCapability, fromCapability } from './keyHelpers.js'
import { KmsClient } from './KmsClient.js'
import { LruCache } from '@interop/lru-memoize'

const CACHE_MAX = 100
const CACHE_TTL = 3000
const JOSE_ALGORITHM_MAP = {
  Sha256HmacKey2019: 'HS256'
}

export class Hmac {
  id?: string
  kmsId?: string
  type?: string
  algorithm?: string
  invocationSigner?: ISigner
  kmsClient: KmsClient
  capability?: IZcap | string
  _cache: LruCache

  /**
   * Creates a new instance of an HMAC.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID for the hmac key.
   * @param {string} [options.kmsId=options.id] - The key ID used to
   *   identify the key with the KMS.
   * @param {string} options.type - The type for the hmac.
   * @param {object} [options.capability] - Do not pass "capability" here;
   *   use `.fromCapability` instead.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Hmac} The new Hmac instance.
   * @see https://tools.ietf.org/html/rfc2104
   */
  constructor({
    id,
    kmsId = id,
    type,
    capability,
    invocationSigner,
    kmsClient = new KmsClient()
  }: {
    id?: string
    kmsId?: string
    type?: string
    capability?: IZcap | string
    invocationSigner?: ISigner
    kmsClient?: KmsClient
  }) {
    assertNoCapability(capability)
    this.id = id
    this.kmsId = kmsId
    this.type = type
    this.algorithm = JOSE_ALGORITHM_MAP[type as keyof typeof JOSE_ALGORITHM_MAP]
    if (!this.algorithm) {
      throw new Error(`Unknown key type "${this.type}".`)
    }
    this.invocationSigner = invocationSigner
    this.kmsClient = kmsClient
    this.capability = undefined
    // entries expire via the cache's own `ttl` (evicted lazily on access);
    // no prune timer is scheduled, so idle instances do not hold the Node
    // event loop open
    this._cache = new LruCache({
      max: CACHE_MAX,
      ttl: CACHE_TTL,
      updateAgeOnGet: true
    })
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {boolean} [options.useCache=true] - Enable the use of a cache.
   *
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({
    data,
    useCache = true
  }: {
    data: Uint8Array
    useCache?: boolean
  }): Promise<Uint8Array> {
    if (!useCache) {
      return this._uncachedSign({ data })
    }

    return this._cache.memoize({
      key: `sign-${base64urlnopad.encode(data)}`,
      fn: () => this._uncachedSign({ data })
    })
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {Uint8Array|string} options.signature - The Uint8Array or
   *   base64url-encoded signature to verify.
   * @param {boolean} [options.useCache=true] - Enable the use of a cache.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({
    data,
    signature,
    useCache = true
  }: {
    data: Uint8Array
    signature: Uint8Array | string
    useCache?: boolean
  }): Promise<boolean> {
    // encode a binary signature once here; the KMS operation accepts the
    // encoded form, so it is not re-encoded downstream
    const encodedSignature =
      typeof signature === 'string'
        ? signature
        : base64urlnopad.encode(signature)
    if (!useCache) {
      return this._uncachedVerify({ data, signature: encodedSignature })
    }

    // the cache key must cover the signature as well: verifying the same
    // data against a different signature must not reuse a cached result;
    // JSON.stringify keeps the (data, signature) pair unambiguous so
    // distinct pairs cannot collide on one key
    return this._cache.memoize({
      key: JSON.stringify([
        'verify',
        base64urlnopad.encode(data),
        encodedSignature
      ]),
      fn: () => this._uncachedVerify({ data, signature: encodedSignature })
    })
  }

  /**
   * Creates a new instance of an hmac key from an authorization capability.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.capability] - The authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Hmac} The new Hmac instance.
   */
  static async fromCapability({
    capability,
    invocationSigner,
    kmsClient = new KmsClient()
  }: {
    capability?: IZcap | string
    invocationSigner?: ISigner
    kmsClient?: KmsClient
  }): Promise<Hmac> {
    return fromCapability({
      KeyClass: Hmac,
      capability,
      invocationSigner,
      kmsClient
    })
  }

  async _uncachedSign({ data }: { data: Uint8Array }): Promise<Uint8Array> {
    const { kmsId: keyId, kmsClient, capability, invocationSigner } = this
    return kmsClient.sign({ keyId, data, capability, invocationSigner })
  }

  async _uncachedVerify({
    data,
    signature
  }: {
    data: Uint8Array
    signature: string
  }): Promise<boolean> {
    const { kmsId: keyId, kmsClient, capability, invocationSigner } = this
    return kmsClient.verify({
      keyId,
      data,
      signature,
      capability,
      invocationSigner
    })
  }
}
