/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import { base64urlnopad } from '@scure/base'
import { DEFAULT_HEADERS, httpClient } from '@interop/http-client'
import { LruCache } from '@interop/lru-memoize'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import type { ISigner, IZcap } from '@interop/data-integrity-core'
import type { KeyDescription, KeystoreConfig } from './types.js'

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:'

// process-wide shared cache for key descriptions:
const KEY_DESCRIPTION_CACHE = new LruCache({
  // 1000 keys at ~1 KiB each would be only ~1 MiB cache size
  max: 1000,
  // 5 min TTL (key descriptions rarely, if ever, change)
  ttl: 1000 * 60 * 5
})

/**
 * @class
 * @classdesc A WebKMS Client used to interface with a KMS.
 * @memberof module:webkms
 */
export class KmsClient {
  keystoreId?: string
  agent?: unknown
  defaultHeaders: Record<string, string>
  allowInsecureLoopback: boolean

  /**
   * Creates a new KmsClient.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keystoreId] - The ID of the keystore
   *   that must be a URL that refers to the keystore's root storage
   *   location; if not given, then a separate capability must be given to
   *   each method called on the client instance.
   * @param {object} [options.httpsAgent] - A Node.js `https.Agent` instance
   *   to use when making requests.
   * @param {object} [options.defaultHeaders] - The HTTP headers to include
   *   with every request.
   * @param {boolean} [options.allowInsecureLoopback=true] - `true` to allow
   *   plain-`http` invocation targets on loopback hosts (`localhost` /
   *   `127.0.0.1` / `[::1]`) as a development exception; `false` to require
   *   `https` for all targets.
   *
   * @returns {KmsClient} The new instance.
   */
  constructor({
    keystoreId,
    httpsAgent,
    defaultHeaders,
    allowInsecureLoopback = true
  }: {
    keystoreId?: string
    httpsAgent?: unknown
    defaultHeaders?: Record<string, string>
    allowInsecureLoopback?: boolean
  } = {}) {
    if (keystoreId) {
      _assert(keystoreId, 'keystoreId', 'string')
    }
    this.keystoreId = keystoreId
    this.agent = httpsAgent
    this.defaultHeaders = { ...DEFAULT_HEADERS, ...defaultHeaders }
    this.allowInsecureLoopback = allowInsecureLoopback
  }

  /**
   * Generates a new cryptographic key in the keystore.
   *
   * @alias webkms.generateKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.type - The key type (e.g. 'AesKeyWrappingKey2019',
   *   or 'Ed25519VerificationKey2020').
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {number} [options.maxCapabilityChainLength] - The max acceptable
   *   length of a capability chain associated with a zcap invocation at
   *   the key's URL.
   * @param {string} [options.publicAlias] - The public alias to use for the
   *   key, if it is an asymmetric key.
   * @param {string} [options.publicAliasTemplate] - The public alias template
   *   to use for the key, if it is an asymmetric key.
   *
   * @returns {Promise<object>} The new key ID and key description for the key.
   */
  async generateKey({
    type,
    capability,
    invocationSigner,
    maxCapabilityChainLength,
    publicAlias,
    publicAliasTemplate
  }: {
    type?: string
    capability?: IZcap | string
    invocationSigner?: ISigner
    maxCapabilityChainLength?: number
    publicAlias?: string
    publicAliasTemplate?: string
  }): Promise<{
    keyId: string
    keyDescription: KeyDescription
  }> {
    _assert(type, 'type', 'string')
    _assert(invocationSigner, 'invocationSigner', 'object')
    if (
      maxCapabilityChainLength !== undefined &&
      !(
        typeof maxCapabilityChainLength === 'number' &&
        Number.isInteger(maxCapabilityChainLength) &&
        maxCapabilityChainLength >= 1 &&
        maxCapabilityChainLength <= 10
      )
    ) {
      throw new Error(
        '"maxCapabilityChainLength" must be an integer between 1 and 10.'
      )
    }
    if (publicAlias !== undefined) {
      _assert(publicAlias, 'publicAlias', 'string')
    }
    if (publicAliasTemplate !== undefined) {
      _assert(publicAliasTemplate, 'publicAliasTemplate', 'string')
    }
    if (publicAlias && publicAliasTemplate) {
      throw new Error(
        'Only one of "publicAlias" and "publicAliasTemplate" may be given.'
      )
    }

    const operation: {
      type: string
      invocationTarget: {
        type: string
        maxCapabilityChainLength?: number
        publicAlias?: string
        publicAliasTemplate?: string
      }
    } = {
      type: 'GenerateKeyOperation',
      invocationTarget: { type }
    }
    if (maxCapabilityChainLength) {
      operation.invocationTarget.maxCapabilityChainLength =
        maxCapabilityChainLength
    }
    if (publicAlias) {
      operation.invocationTarget.publicAlias = publicAlias
    } else if (publicAliasTemplate) {
      operation.invocationTarget.publicAliasTemplate = publicAliasTemplate
    }

    let target
    if (capability) {
      target = _resolveTarget({ capability })
    } else {
      // keys are created under the keystore's `/keys` collection
      target = _resolveTarget({ keystoreId: this.keystoreId })
      target.url = `${target.url}/keys`
    }
    const data = (await this._invoke({
      ...target,
      json: operation,
      invocationSigner,
      capabilityAction: 'generateKey',
      message: 'Error generating key.',
      duplicateMessage: 'Duplicate error.'
    })) as { keyId?: unknown; keyDescription?: unknown } | undefined
    const { keyId, keyDescription } = data ?? {}
    if (!(
      typeof keyId === 'string' &&
      keyDescription &&
      typeof keyDescription === 'object'
    )) {
      throw new Error(
        'Invalid WebKMS server response: ' +
          'missing "keyId" or "keyDescription".'
      )
    }
    return {
      keyId,
      keyDescription: keyDescription as KeyDescription
    }
  }

  /**
   * Gets the key description for the given key ID.
   *
   * @alias webkms.getKeyDescription
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keyId] - The ID of the key.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {boolean} [options.useCache=true] - `true` to use a cache when
   *   retrieving the key description, `false` not to.
   *
   * @returns {Promise<object>} The key description.
   */
  async getKeyDescription({
    keyId,
    capability,
    invocationSigner,
    useCache = true
  }: {
    keyId?: string
    capability?: IZcap | string
    invocationSigner?: ISigner
    useCache?: boolean
  }): Promise<KeyDescription> {
    _assert(invocationSigner, 'invocationSigner', 'object')
    if (!capability) {
      _assert(keyId, 'keyId', 'string')
    }
    const target = _resolveTarget({ capability, keyId })

    if (!useCache) {
      return this._getUncachedKeyDescription({ ...target, invocationSigner })
    }

    return KEY_DESCRIPTION_CACHE.memoize({
      key: JSON.stringify([
        target.url,
        typeof target.capability === 'string'
          ? target.capability
          : target.capability.id || target.capability,
        invocationSigner.id
      ]),
      fn: () => this._getUncachedKeyDescription({ ...target, invocationSigner })
    })
  }

  /**
   * Lists the public key descriptions in a keystore (a fork extension beyond
   * upstream webkms-switch). Follows the server's `next` cursor to exhaustion
   * and returns every key's description, sorted by the server's local id.
   * Never returns secret material.
   *
   * @alias webkms.listKeys
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The authorization capability to
   *   authorize the invocation; the keystore's root zcap is used if not
   *   provided (requires `keystoreId` on the client). A delegated capability's
   *   `invocationTarget` must be the `<keystoreId>/keys` collection URL.
   * @param {object} options.invocationSigner - An API with an `id` property and
   *   a `sign` function for signing a capability invocation.
   * @param {number} [options.maxPages=1000] - Safety cap on pages followed, to
   *   bound a buggy/hostile server that never terminates the cursor.
   *
   * @returns {Promise<Array>} The keystore's public key descriptions.
   */
  async listKeys({
    capability,
    invocationSigner,
    maxPages = 1000
  }: {
    capability?: IZcap | string
    invocationSigner?: ISigner
    maxPages?: number
  }): Promise<KeyDescription[]> {
    _assert(invocationSigner, 'invocationSigner', 'object')

    // resolve the first-page target, mirroring `generateKey`; the same
    // capability (root or delegated) is reused for every page
    let target
    if (capability) {
      target = _resolveTarget({ capability })
    } else {
      const { keystoreId } = this
      if (!keystoreId) {
        throw new TypeError(
          '"capability" is required if "keystoreId" was not provided to the ' +
            'KmsClient constructor.'
        )
      }
      // keys are listed under the keystore's `/keys` collection
      target = _resolveTarget({ keystoreId })
      target.url = `${target.url}/keys`
    }

    // the `next` cursor is origin-relative; a signed invocation must never be
    // coaxed off the keystore origin by a hostile/buggy server
    const keystoreOrigin = new URL(target.url).origin

    const keys: KeyDescription[] = []
    let url = target.url
    for (let page = 0; ; page++) {
      if (page >= maxPages) {
        throw new Error(
          `Refusing to follow more than ${maxPages} list-keys pages.`
        )
      }
      const data = (await this._invoke({
        url,
        capability: target.capability,
        method: 'get',
        invocationSigner,
        capabilityAction: 'read',
        message: 'Error listing keys.',
        notFoundMessage: 'Keystore not found.',
        expect: 'object'
      })) as { results?: unknown; next?: unknown }

      if (!Array.isArray(data.results)) {
        throw new Error('Invalid WebKMS server response: missing "results".')
      }
      keys.push(...(data.results as KeyDescription[]))

      if (data.next === undefined) {
        break
      }
      if (typeof data.next !== 'string') {
        throw new Error(
          'Invalid WebKMS server response: "next" must be a string.'
        )
      }
      const nextUrl = new URL(data.next, url)
      if (nextUrl.origin !== keystoreOrigin) {
        throw new Error(
          'Refusing to follow a cross-origin list-keys "next" ' +
            `(${nextUrl.origin}).`
        )
      }
      url = nextUrl.toString()
    }
    return keys
  }

  /**
   * Revoke a delegated capability.
   *
   * @alias webkms.revokeCapability
   *
   * @param {object} options - The options to use.
   * @param {object} options.capabilityToRevoke - The capability to revoke.
   * @param {string} [options.capability] - The zcap authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves once the operation completes.
   */
  async revokeCapability({
    capabilityToRevoke,
    capability,
    invocationSigner
  }: {
    capabilityToRevoke: IZcap
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<void> {
    _assert(capabilityToRevoke, 'capabilityToRevoke', 'object')
    _assert(invocationSigner, 'invocationSigner', 'object')

    let target
    if (capability) {
      target = _resolveTarget({ capability })
    } else {
      let { keystoreId } = this
      if (!keystoreId) {
        // since no `keystoreId` was set and no `capability` with an
        // invocation target that can be parsed was given, get the keystore
        // ID from the capability that is to be revoked -- presuming it is a
        // WebKMS key (if revoking any other capability, the `keystoreId`
        // must be set or a `capability` passed to invoke)
        const invocationTarget = KmsClient._getInvocationTarget({
          capability: capabilityToRevoke
        })
        const idx = invocationTarget.lastIndexOf('/keys/')
        if (idx === -1) {
          throw new Error(
            `Invalid WebKMS key invocation target (${invocationTarget}).`
          )
        }
        keystoreId = invocationTarget.slice(0, idx)
      }
      const url =
        `${keystoreId}/zcaps/revocations/` +
        `${encodeURIComponent(capabilityToRevoke.id)}`
      target = { url, capability: _getRootZcapId({ url }) }
    }

    await this._invoke({
      ...target,
      json: capabilityToRevoke,
      invocationSigner,
      capabilityAction: 'write',
      message: 'Error revoking zCap.',
      notFoundMessage: 'zCap not found.',
      duplicateMessage: 'Duplicate error.'
    })
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @alias webkms.wrapKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the wrapping key to use.
   * @param {Uint8Array} options.unwrappedKey - The unwrapped key material as
   *   a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The wrapped key bytes.
   */
  async wrapKey({
    kekId,
    unwrappedKey,
    capability,
    invocationSigner
  }: {
    kekId?: string
    unwrappedKey: Uint8Array
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<Uint8Array> {
    _assert(kekId, 'kekId', 'string')
    _assert(unwrappedKey, 'unwrappedKey', 'Uint8Array')
    _assert(invocationSigner, 'invocationSigner', 'object')

    const operation = {
      type: 'WrapKeyOperation',
      invocationTarget: kekId,
      unwrappedKey: base64urlnopad.encode(unwrappedKey)
    }

    const data = await this._invoke({
      ..._resolveTarget({ capability, keyId: kekId }),
      json: operation,
      invocationSigner,
      capabilityAction: 'wrapKey',
      message: 'Error wrapping key.',
      notFoundMessage: 'Key encryption key not found.'
    })
    return _decodeResponseBytes({ data, field: 'wrappedKey' })
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @alias webkms.unwrapKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the unwrapping key to use.
   * @param {Uint8Array|string} options.wrappedKey - The wrapped key material
   *   as a Uint8Array or base64url-encoded string.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array|null>} Resolves to the unwrapped key material
   *   or null if the unwrapping failed because the key did not match.
   */
  async unwrapKey({
    kekId,
    wrappedKey,
    capability,
    invocationSigner
  }: {
    kekId?: string
    wrappedKey: Uint8Array | string
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<Uint8Array | null> {
    _assert(kekId, 'kekId', 'string')
    _assert(wrappedKey, 'wrappedKey', ['string', 'Uint8Array'])
    _assert(invocationSigner, 'invocationSigner', 'object')

    if (wrappedKey instanceof Uint8Array) {
      // base64url-encode wrappedKey for transport
      wrappedKey = base64urlnopad.encode(wrappedKey)
    }

    const operation = {
      type: 'UnwrapKeyOperation',
      invocationTarget: kekId,
      wrappedKey
    }

    const data = (await this._invoke({
      ..._resolveTarget({ capability, keyId: kekId }),
      json: operation,
      invocationSigner,
      capabilityAction: 'unwrapKey',
      message: 'Error unwrapping key.',
      notFoundMessage: 'Key encryption key not found.'
    })) as { unwrappedKey?: unknown } | undefined
    if (data?.unwrappedKey === null) {
      // the KMS reported that the key did not match; return the documented
      // `null` sentinel
      return null
    }
    return _decodeResponseBytes({ data, field: 'unwrappedKey' })
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @alias webkms.sign
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({
    keyId,
    data,
    capability,
    invocationSigner
  }: {
    keyId?: string
    data: Uint8Array
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<Uint8Array> {
    _assert(keyId, 'keyId', 'string')
    _assert(data, 'data', 'Uint8Array')
    _assert(invocationSigner, 'invocationSigner', 'object')

    const operation = {
      type: 'SignOperation',
      invocationTarget: keyId,
      verifyData: base64urlnopad.encode(data)
    }

    const result = await this._invoke({
      ..._resolveTarget({ capability, keyId }),
      json: operation,
      invocationSigner,
      capabilityAction: 'sign',
      message: 'Error during "sign" operation.'
    })
    return _decodeResponseBytes({ data: result, field: 'signatureValue' })
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @alias webkms.verify
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to verify as a Uint8Array.
   * @param {Uint8Array|string} options.signature - The signature to verify;
   *   it may be passed either a base64url-encoded string or a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({
    keyId,
    data,
    signature,
    capability,
    invocationSigner
  }: {
    keyId?: string
    data: Uint8Array
    signature: Uint8Array | string
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<boolean> {
    _assert(keyId, 'keyId', 'string')
    _assert(data, 'data', 'Uint8Array')
    _assert(signature, 'signature', ['string', 'Uint8Array'])
    _assert(invocationSigner, 'invocationSigner', 'object')

    if (signature instanceof Uint8Array) {
      // base64url-encode signature for transport
      signature = base64urlnopad.encode(signature)
    }

    const operation = {
      type: 'VerifyOperation',
      invocationTarget: keyId,
      verifyData: base64urlnopad.encode(data),
      signatureValue: signature
    }

    const result = (await this._invoke({
      ..._resolveTarget({ capability, keyId }),
      json: operation,
      invocationSigner,
      capabilityAction: 'verify',
      message: 'Error during "verify" operation.'
    })) as { verified?: unknown } | undefined
    const verified = result?.verified
    if (typeof verified !== 'boolean') {
      throw new Error('Invalid WebKMS server response: missing "verified".')
    }
    return verified
  }

  /**
   * Derives a shared secret via the given peer public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   *
   * @alias webkms.deriveSecret
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the key agreement key to use.
   * @param {object} options.publicKey - The public key to compute the shared
   *   secret against; the public key type must match the key agreement key's
   *   type.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The shared secret bytes.
   */
  async deriveSecret({
    keyId,
    publicKey,
    capability,
    invocationSigner
  }: {
    keyId?: string
    publicKey: KeyDescription
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<Uint8Array> {
    _assert(keyId, 'keyId', 'string')
    _assert(publicKey, 'publicKey', 'object')
    _assert(invocationSigner, 'invocationSigner', 'object')

    const operation = {
      type: 'DeriveSecretOperation',
      invocationTarget: keyId,
      publicKey
    }

    const result = await this._invoke({
      ..._resolveTarget({ capability, keyId }),
      json: operation,
      invocationSigner,
      capabilityAction: 'deriveSecret',
      message: 'Error during "deriveSecret" operation.',
      notFoundMessage: 'Key agreement key not found.'
    })
    return _decodeResponseBytes({ data: result, field: 'secret' })
  }

  /**
   * Update a keystore using the given configuration.
   *
   * @alias webkms.updateKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The ZCAP authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {string} options.config - The keystore's configuration.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves to the new keystore configuration.
   */
  async updateKeystore({
    capability,
    config,
    invocationSigner
  }: {
    capability?: IZcap | string
    config: KeystoreConfig
    invocationSigner?: ISigner
  }): Promise<KeystoreConfig> {
    _assert(invocationSigner, 'invocationSigner', 'object')

    const { keystoreId } = this
    if (!(keystoreId || capability)) {
      throw new TypeError(
        '"capability" is required if "keystoreId" was not provided ' +
          'to the KmsClient constructor.'
      )
    }
    const data = await this._invoke({
      ..._resolveTarget({ capability, keystoreId }),
      json: config,
      invocationSigner,
      capabilityAction: 'write',
      message: 'Error during "update keystore" operation.',
      expect: 'object'
    })
    return data as KeystoreConfig
  }

  /**
   * Gets the configuration for a keystore by its ID.
   *
   * @alias webkms.getKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The ZCAP authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves to the configuration for the keystore.
   */
  async getKeystore({
    capability,
    invocationSigner
  }: {
    capability?: IZcap | string
    invocationSigner?: ISigner
  }): Promise<KeystoreConfig> {
    _assert(invocationSigner, 'invocationSigner', 'object')

    const { keystoreId } = this
    if (!(keystoreId || capability)) {
      throw new TypeError(
        '"capability" is required if "keystoreId" was not provided ' +
          'to the KmsClient constructor.'
      )
    }
    const data = await this._invoke({
      ..._resolveTarget({ capability, keystoreId }),
      method: 'get',
      invocationSigner,
      capabilityAction: 'read',
      message: 'Error during "get keystore" operation.',
      expect: 'object'
    })
    return data as KeystoreConfig
  }

  /**
   * Creates a new keystore using the given configuration.
   *
   * @alias webkms.createKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} options.url - The url to post the configuration to.
   * @param {string} options.config - The keystore's configuration.
   * @param {string|object} [options.capability] - The zcap authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {object} [options.httpsAgent] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the newly
   *   created keystore.
   */
  static async createKeystore({
    url,
    config,
    capability,
    invocationSigner,
    httpsAgent
  }: {
    url?: string
    config?: KeystoreConfig
    capability?: IZcap | string
    invocationSigner?: ISigner
    httpsAgent?: unknown
  } = {}): Promise<KeystoreConfig> {
    _assert(url, 'url', 'string')
    _assert(config, 'config', 'object')
    _assert(config.controller, 'config.controller', 'string')
    _assert(invocationSigner, 'invocationSigner', 'object')

    const data = (await _invoke({
      url,
      capability: capability ?? _getRootZcapId({ url }),
      json: config,
      invocationSigner,
      capabilityAction: 'write',
      message: 'Error during "create keystore" operation.',
      duplicateMessage: 'Duplicate keystore.',
      expect: 'object',
      agent: httpsAgent,
      headers: DEFAULT_HEADERS
    })) as KeystoreConfig
    if (typeof data.id !== 'string') {
      throw new Error('Invalid WebKMS server response: missing keystore "id".')
    }
    return data
  }

  async _getUncachedKeyDescription({
    url,
    capability,
    invocationSigner
  }: {
    url: string
    capability: IZcap | string
    invocationSigner?: ISigner
  }): Promise<KeyDescription> {
    _assert(invocationSigner, 'invocationSigner', 'object')

    const data = await this._invoke({
      url,
      capability,
      method: 'get',
      invocationSigner,
      capabilityAction: 'read',
      message: 'Error fetching key description.',
      notFoundMessage: 'Key description not found.',
      expect: 'object'
    })
    return data as KeyDescription
  }

  /**
   * Signs and sends a single capability invocation to the KMS using this
   * client's agent, headers, and target policy.
   *
   * @param {object} options - The options to use; see the module-level
   *   `_invoke`.
   *
   * @returns {Promise<unknown>} The parsed response body.
   */
  async _invoke(options: InvokeOptions): Promise<unknown> {
    const { agent, defaultHeaders: headers, allowInsecureLoopback } = this
    return _invoke({ ...options, agent, headers, allowInsecureLoopback })
  }

  static _getInvocationTarget(options: { capability: IZcap | string }): string
  static _getInvocationTarget(options: {
    capability?: IZcap | string | null
  }): string | null
  static _getInvocationTarget({
    capability
  }: {
    capability?: IZcap | string | null
  }): string | null {
    // no capability, so no invocation target
    if (capability === undefined || capability === null) {
      return null
    }

    let invocationTarget
    if (typeof capability === 'string') {
      if (!capability.startsWith(ZCAP_ROOT_PREFIX)) {
        throw new Error(
          'If "capability" is a string, it must be a root capability.'
        )
      }
      invocationTarget = decodeURIComponent(
        capability.substring(ZCAP_ROOT_PREFIX.length)
      )
    } else if (typeof capability === 'object') {
      ;({ invocationTarget } = capability)
    }

    if (!(
      typeof invocationTarget === 'string' &&
      _isAllowedTarget({ url: invocationTarget, allowInsecureLoopback: true })
    )) {
      throw new TypeError(
        '"invocationTarget" from capability must be an "https" URL ' +
          '(or an "http" URL on a loopback host, for development).'
      )
    }

    return invocationTarget
  }
}

/**
 * The per-operation options for `_invoke` (shared by the instance wrapper
 * and the module-level function).
 */
interface InvokeOptions {
  /** The invocation target URL. */
  url: string
  /** The authorization capability. */
  capability: IZcap | string
  /** The HTTP method (default 'post'). */
  method?: 'get' | 'post'
  /** The JSON body to send (POST only). */
  json?: object
  /** An API for signing a capability invocation. */
  invocationSigner: ISigner
  /** The capability action. */
  capabilityAction: string
  /** The error message to use on failure. */
  message: string
  /** Optional message for 404s. */
  notFoundMessage?: string
  /** If given, map a 409 response to a `DuplicateError` with this message. */
  duplicateMessage?: string
  /** If 'object', require the response body to be an object. */
  expect?: 'object'
}

/**
 * Signs and sends a single capability invocation to the KMS: validates the
 * target URL scheme, signs the invocation headers, performs the HTTP
 * request, maps any failure through `_handleClientError`, and (optionally)
 * asserts the response body shape.
 *
 * @param {object} options - The options to use; `InvokeOptions` plus the
 *   client context.
 * @param {object} [options.agent] - A Node.js `https.Agent` instance.
 * @param {object} options.headers - The HTTP headers to include.
 * @param {boolean} [options.allowInsecureLoopback=true] - Allow plain-`http`
 *   targets on loopback hosts.
 *
 * @returns {Promise<unknown>} The parsed response body.
 */
async function _invoke({
  url,
  capability,
  method = 'post',
  json,
  invocationSigner,
  capabilityAction,
  message,
  notFoundMessage,
  duplicateMessage,
  expect,
  agent,
  headers,
  allowInsecureLoopback = true
}: InvokeOptions & {
  agent?: unknown
  headers: Record<string, string>
  allowInsecureLoopback?: boolean
}): Promise<unknown> {
  if (!_isAllowedTarget({ url, allowInsecureLoopback })) {
    throw new TypeError(
      `Refusing to send a KMS invocation to (${url}): the target must be ` +
        'an "https" URL' +
        (allowInsecureLoopback
          ? ' (or an "http" URL on a loopback host, for development).'
          : '.')
    )
  }

  let data: unknown
  try {
    const signedHeaders = await signCapabilityInvocation({
      url,
      method,
      headers,
      ...(json === undefined ? {} : { json }),
      capability,
      invocationSigner,
      capabilityAction
    })

    // send request
    const result =
      method === 'get'
        ? await httpClient.get(url, { agent, headers: signedHeaders })
        : await httpClient.post(url, { agent, headers: signedHeaders, json })
    data = result.data
  } catch (e) {
    _handleClientError({
      message,
      notFoundMessage,
      duplicateMessage,
      cause: e
    })
  }
  if (expect === 'object' && (data === null || typeof data !== 'object')) {
    throw new Error('Invalid WebKMS server response: expected an object body.')
  }
  return data
}

/**
 * Resolves the invocation target URL and capability for a KMS operation:
 * uses the given capability's invocation target when a capability is passed,
 * otherwise falls back to the key/keystore ID and its root zcap (a key's
 * root zcap is rooted at its keystore's URL).
 *
 * @param {object} options - Options hashmap.
 * @param {string|object} [options.capability] - The authorization capability.
 * @param {string} [options.keyId] - The key ID fallback target.
 * @param {string} [options.keystoreId] - The keystore ID fallback target.
 *
 * @returns {{url: string, capability: string|object}} The resolved target.
 */
function _resolveTarget({
  capability,
  keyId,
  keystoreId
}: {
  capability?: IZcap | string
  keyId?: string
  keystoreId?: string
}): { url: string; capability: IZcap | string } {
  if (capability) {
    return { url: KmsClient._getInvocationTarget({ capability }), capability }
  }
  const id = keyId ?? keystoreId
  if (id === undefined) {
    throw new TypeError(
      'Either a "capability" or a key/keystore ID is required.'
    )
  }
  let rootTarget = id
  if (keyId !== undefined) {
    const idx = keyId.lastIndexOf('/keys/')
    if (idx === -1) {
      throw new Error(`Invalid WebKMS key ID (${keyId}).`)
    }
    rootTarget = keyId.slice(0, idx)
  }
  return { url: id, capability: _getRootZcapId({ url: rootTarget }) }
}

/**
 * Decodes base64url-encoded data, tolerating padded base64url and standard
 * (`+`/`/` alphabet) base64: some KMS servers and proxies emit those forms,
 * and the strict `@scure/base` base64url decoder rejects them.
 *
 * @param {string} value - The base64url/base64-encoded data.
 *
 * @returns {Uint8Array} The decoded bytes.
 */
function _decodeBase64(value: string): Uint8Array {
  const normalized = value
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  return base64urlnopad.decode(normalized)
}

/**
 * Reads a base64url-encoded field from a KMS response body and decodes it,
 * throwing a clear, attributed error when the field is missing or malformed.
 *
 * @param {object} options - Options hashmap.
 * @param {unknown} options.data - The parsed response body.
 * @param {string} options.field - The name of the field to decode.
 *
 * @returns {Uint8Array} The decoded bytes.
 */
function _decodeResponseBytes({
  data,
  field
}: {
  data: unknown
  field: string
}): Uint8Array {
  const value = (data as Record<string, unknown> | null | undefined)?.[field]
  if (typeof value !== 'string') {
    throw new Error(`Invalid WebKMS server response: missing "${field}".`)
  }
  try {
    return _decodeBase64(value)
  } catch (cause) {
    throw new Error(
      `Invalid WebKMS server response: "${field}" is not base64-encoded.`,
      { cause }
    )
  }
}

/**
 * Checks that a KMS invocation target is an acceptable URL: `https:`, or --
 * if `allowInsecureLoopback` is set, as a development exception -- plain
 * `http:` on a loopback host (`localhost` / `127.0.0.1` / `[::1]`), so
 * zcaps work against a KMS on a local dev server.
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.url - The invocation target URL.
 * @param {boolean} options.allowInsecureLoopback - Allow the plain-`http`
 *   loopback exception.
 *
 * @returns {boolean} True if the target is acceptable.
 */
function _isAllowedTarget({
  url,
  allowInsecureLoopback
}: {
  url: string
  allowInsecureLoopback: boolean
}): boolean {
  if (url.startsWith('https://')) {
    return true
  }
  if (!allowInsecureLoopback || !url.startsWith('http://')) {
    return false
  }
  let hostname
  try {
    ;({ hostname } = new URL(url))
  } catch {
    return false
  }
  return (
    hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
  )
}

/**
 * @param {object} options - Options hashmap.
 * @param {string} options.message - Error message.
 * @param {Error} options.cause - Source error for wrapping.
 * @param {string} [options.notFoundMessage] - Optional 'not found' message.
 * @param {string} [options.duplicateMessage] - If given, wrap a 409 cause in
 *   a `DuplicateError` with this message before mapping.
 */
function _handleClientError({
  message,
  cause,
  notFoundMessage = 'Key not found',
  duplicateMessage
}: {
  message: string
  cause: any
  notFoundMessage?: string
  duplicateMessage?: string
}): never {
  if (duplicateMessage && cause.status === 409) {
    const duplicate: Error & { cause?: unknown } = new Error(duplicateMessage)
    duplicate.name = 'DuplicateError'
    duplicate.cause = cause
    cause = duplicate
  }

  let error: Error & { status?: number; data?: unknown }
  const errorMessage = message.slice(0, -1)
  if (cause.status === 404) {
    // e.g. 'Error getting key description: Key description not found'
    error = new Error(`${errorMessage}: ${notFoundMessage}`)
    error.status = 404
  } else {
    error = new Error(`WebKMS client error: ${errorMessage}`)
    if (cause.data) {
      error.data = cause.data
    }
    if (cause.status) {
      error.status = cause.status
    }
  }

  if (!error.message.endsWith('.')) {
    error.message += '.'
  }

  error.cause = cause

  throw error
}

function _assert(
  variable: any,
  name: string,
  types: string | string[]
): asserts variable {
  if (!Array.isArray(types)) {
    types = [types]
  }
  const type = variable instanceof Uint8Array ? 'Uint8Array' : typeof variable
  if (!types.includes(type)) {
    throw new TypeError(
      `"${name}" must be ${types.length === 1 ? 'a' : 'one of'} ` +
        `${types.join(', ')}.`
    )
  }
}

/**
 * Returns the ID of the root zcap for the given target URL.
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.url - The target URL the root zcap authorizes.
 *
 * @returns {string} The root zcap ID (a `urn:zcap:root:` URN).
 */
function _getRootZcapId({ url }: { url: string }): string {
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`
}
