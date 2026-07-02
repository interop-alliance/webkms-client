/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import { base64urlnopad } from '@scure/base'
import { DEFAULT_HEADERS, httpClient } from '@interop/http-client'
import type { HttpResponse } from '@interop/http-client'
import { LruCache } from '@interop/lru-memoize'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import type { IZcap } from '@interop/http-signature-zcap-invoke'
import type {
  Capability,
  InvocationSigner,
  KeyDescription,
  KeystoreConfig
} from './types.js'

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
   *
   * @returns {KmsClient} The new instance.
   */
  constructor({
    keystoreId,
    httpsAgent,
    defaultHeaders
  }: {
    keystoreId?: string
    httpsAgent?: unknown
    defaultHeaders?: Record<string, string>
  } = {}) {
    if (keystoreId) {
      _assert(keystoreId, 'keystoreId', 'string')
    }
    this.keystoreId = keystoreId
    this.agent = httpsAgent
    this.defaultHeaders = { ...DEFAULT_HEADERS, ...defaultHeaders }
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
    capability?: Capability
    invocationSigner?: InvocationSigner
    maxCapabilityChainLength?: number
    publicAlias?: string
    publicAliasTemplate?: string
  }): Promise<{ keyId: string; keyDescription: KeyDescription }> {
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

    const { keystoreId } = this
    const target = _resolveTarget({
      capability,
      keystoreId,
      url: `${keystoreId}/keys`
    })
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
    return { keyId, keyDescription: keyDescription as KeyDescription }
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capabilityToRevoke: Exclude<Capability, string>
    capability?: Capability
    invocationSigner?: InvocationSigner
  }): Promise<void> {
    _assert(capabilityToRevoke, 'capabilityToRevoke', 'object')
    _assert(invocationSigner, 'invocationSigner', 'object')

    let { keystoreId } = this
    if (!keystoreId && !capability) {
      // since no `keystoreId` was set and no `capability` with an invocation
      // target that can be parsed was given, get the keystore ID from the
      // capability that is to be revoked -- presuming it is a WebKMS key (if
      // revoking any other capability, the `keystoreId` must be set or a
      // `capability` passed to invoke)
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

    const url = capability
      ? KmsClient._getInvocationTarget({ capability })
      : `${keystoreId}/zcaps/revocations/` +
        `${encodeURIComponent(capabilityToRevoke.id as string)}`
    if (!capability) {
      capability = `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`
    }

    await this._invoke({
      url,
      capability,
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
    capability?: Capability
    config: KeystoreConfig
    invocationSigner?: InvocationSigner
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
      message: 'Error during "update keystore" operation.'
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
    capability?: Capability
    invocationSigner?: InvocationSigner
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
      message: 'Error during "get keystore" operation.'
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
    capability?: Capability
    invocationSigner?: InvocationSigner
    httpsAgent?: unknown
  } = {}): Promise<KeystoreConfig> {
    _assert(url, 'url', 'string')
    _assert(config, 'config', 'object')
    _assert(config.controller, 'config.controller', 'string')
    _assert(invocationSigner, 'invocationSigner', 'object')

    if (!capability) {
      capability = `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`
    }

    let result: HttpResponse
    try {
      const headers = await signCapabilityInvocation({
        url,
        method: 'post',
        headers: DEFAULT_HEADERS,
        json: config,
        capability: capability as string | IZcap,
        invocationSigner,
        capabilityAction: 'write'
      })

      // send request
      result = await httpClient.post(url, {
        agent: httpsAgent,
        headers,
        json: config
      })
    } catch (e) {
      _handleClientError({
        message: 'Error during "create keystore" operation.',
        cause: e
      })
    }

    _assert(result.data, 'result.data', 'object')
    const data = result.data as KeystoreConfig
    _assert(data.id, 'result.data.id', 'string')
    return data
  }

  async _getUncachedKeyDescription({
    url,
    capability,
    invocationSigner
  }: {
    url: string
    capability: Capability
    invocationSigner?: InvocationSigner
  }): Promise<KeyDescription> {
    _assert(invocationSigner, 'invocationSigner', 'object')

    const data = await this._invoke({
      url,
      capability,
      method: 'get',
      invocationSigner,
      capabilityAction: 'read',
      message: 'Error fetching key description.',
      notFoundMessage: 'Key description not found.'
    })
    return data as KeyDescription
  }

  /**
   * Signs and sends a single capability invocation to the KMS: signs the
   * invocation headers, performs the HTTP request, and maps any failure
   * through `_handleClientError`.
   *
   * @param {object} options - The options to use.
   * @param {string} options.url - The invocation target URL.
   * @param {string|object} options.capability - The authorization capability.
   * @param {string} [options.method='post'] - The HTTP method.
   * @param {object} [options.json] - The JSON body to send (POST only).
   * @param {object} options.invocationSigner - An API for signing a
   *   capability invocation.
   * @param {string} options.capabilityAction - The capability action.
   * @param {string} options.message - The error message to use on failure.
   * @param {string} [options.notFoundMessage] - Optional message for 404s.
   * @param {string} [options.duplicateMessage] - If given, map a 409 response
   *   to a `DuplicateError` with this message.
   *
   * @returns {Promise<unknown>} The parsed response body.
   */
  async _invoke({
    url,
    capability,
    method = 'post',
    json,
    invocationSigner,
    capabilityAction,
    message,
    notFoundMessage,
    duplicateMessage
  }: {
    url: string
    capability: Capability
    method?: 'get' | 'post'
    json?: object
    invocationSigner: InvocationSigner
    capabilityAction: string
    message: string
    notFoundMessage?: string
    duplicateMessage?: string
  }): Promise<unknown> {
    try {
      const headers = await signCapabilityInvocation({
        url,
        method,
        headers: this.defaultHeaders,
        ...(json === undefined ? {} : { json }),
        capability: capability as string | IZcap,
        invocationSigner,
        capabilityAction
      })

      // send request
      const { agent } = this
      const result =
        method === 'get'
          ? await httpClient.get(url, { agent, headers })
          : await httpClient.post(url, { agent, headers, json })
      return result.data
    } catch (e) {
      _handleClientError({
        message,
        notFoundMessage,
        duplicateMessage,
        cause: e
      })
    }
  }

  static _getInvocationTarget(options: { capability: Capability }): string
  static _getInvocationTarget(options: {
    capability?: Capability | null
  }): string | null
  static _getInvocationTarget({
    capability
  }: {
    capability?: Capability | null
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
      _isAllowedInvocationTarget({ invocationTarget })
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
 * Resolves the invocation target URL and capability for a KMS operation:
 * uses the given capability's invocation target when a capability is passed,
 * otherwise falls back to the key/keystore ID (or the given fallback `url`)
 * and its root zcap.
 *
 * @param {object} options - Options hashmap.
 * @param {string|object} [options.capability] - The authorization capability.
 * @param {string} [options.keyId] - The key ID fallback target.
 * @param {string} [options.keystoreId] - The keystore ID fallback target.
 * @param {string} [options.url] - An explicit fallback target URL.
 *
 * @returns {{url: string, capability: string|object}} The resolved target.
 */
function _resolveTarget({
  capability,
  keyId,
  keystoreId,
  url
}: {
  capability?: Capability
  keyId?: string
  keystoreId?: string
  url?: string
}): { url: string; capability: Capability } {
  if (capability) {
    return { url: KmsClient._getInvocationTarget({ capability }), capability }
  }
  const id = keyId ?? keystoreId
  if (id === undefined) {
    throw new TypeError(
      'Either a "capability" or a key/keystore ID is required.'
    )
  }
  return { url: url ?? id, capability: _getRootZcapId({ keyId, keystoreId }) }
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
 * Checks that a capability's invocation target is an acceptable URL:
 * `https:`, or -- as a development exception -- plain `http:` on a loopback
 * host (`localhost` / `127.0.0.1` / `[::1]`), so delegated zcaps work
 * against a KMS on a local dev server.
 *
 * @param {object} options - Options hashmap.
 * @param {string} options.invocationTarget - The invocation target URL.
 *
 * @returns {boolean} True if the target is acceptable.
 */
function _isAllowedInvocationTarget({
  invocationTarget
}: {
  invocationTarget: string
}): boolean {
  if (invocationTarget.startsWith('https://')) {
    return true
  }
  if (!invocationTarget.startsWith('http://')) {
    return false
  }
  let hostname
  try {
    ;({ hostname } = new URL(invocationTarget))
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

function _getRootZcapId({
  keystoreId,
  keyId
}: {
  keystoreId?: string
  keyId?: string
}): string {
  let suffix: string
  if (keyId) {
    const idx = keyId.lastIndexOf('/keys/')
    if (idx === -1) {
      throw new Error(`Invalid WebKMS key ID (${keyId}).`)
    }
    suffix = keyId.slice(0, idx)
  } else if (keystoreId) {
    suffix = keystoreId
  } else {
    throw new TypeError('Either "keyId" or "keystoreId" is required.')
  }
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(suffix)}`
}
