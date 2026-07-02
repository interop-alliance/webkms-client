/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { base64urlnopad } from '@scure/base'

const { postMock, getMock, signInvocationMock } = vi.hoisted(() => ({
  postMock: vi.fn(),
  getMock: vi.fn(),
  signInvocationMock: vi.fn()
}))

vi.mock('@interop/http-client', () => ({
  DEFAULT_HEADERS: { Accept: 'application/ld+json, application/json' },
  httpClient: { post: postMock, get: getMock }
}))

vi.mock('@interop/http-signature-zcap-invoke', () => ({
  signCapabilityInvocation: signInvocationMock
}))

import { KmsClient } from '../../src/index.js'

const keystoreId = 'https://kms.example.com/kms/keystores/z1'
const keyId = `${keystoreId}/keys/z2`
const invocationSigner = {
  id: 'did:key:z6MkTest#z6MkTest',
  sign: async () => new Uint8Array(64)
}

describe('KmsClient operations (mocked transport)', () => {
  let client: KmsClient

  beforeEach(() => {
    postMock.mockReset()
    getMock.mockReset()
    signInvocationMock.mockReset()
    signInvocationMock.mockResolvedValue({})
    client = new KmsClient()
  })

  describe('sign', () => {
    it('decodes an unpadded base64url signatureValue', async () => {
      const signature = Uint8Array.from([1, 2, 3, 255, 254])
      postMock.mockResolvedValue({
        data: { signatureValue: base64urlnopad.encode(signature) }
      })
      const result = await client.sign({
        keyId,
        data: new Uint8Array([1]),
        invocationSigner
      })
      expect(result).toEqual(signature)
      // no capability: targets the key URL with its root zcap
      expect(postMock).toHaveBeenCalledWith(keyId, expect.anything())
    })

    it('throws a clear error when signatureValue is missing', async () => {
      postMock.mockResolvedValue({ data: {} })
      await expect(
        client.sign({ keyId, data: new Uint8Array([1]), invocationSigner })
      ).rejects.toThrow(
        'Invalid WebKMS server response: missing "signatureValue".'
      )
    })
  })

  describe('wrapKey', () => {
    it('accepts a standard (padded, +/ alphabet) base64 wrappedKey', async () => {
      const bytes = Uint8Array.from([255, 255, 254, 255])
      const standardBase64 = Buffer.from(bytes).toString('base64')
      // precondition: the fixture actually exercises `+`/`/`/`=`
      expect(standardBase64).toBe('///+/w==')
      postMock.mockResolvedValue({ data: { wrappedKey: standardBase64 } })
      const result = await client.wrapKey({
        kekId: keyId,
        unwrappedKey: new Uint8Array([1]),
        invocationSigner
      })
      expect(result).toEqual(bytes)
    })

    it('accepts a padded base64url wrappedKey', async () => {
      const bytes = Uint8Array.from([255, 255, 254, 255])
      const paddedBase64url = base64urlnopad.encode(bytes) + '=='
      postMock.mockResolvedValue({ data: { wrappedKey: paddedBase64url } })
      const result = await client.wrapKey({
        kekId: keyId,
        unwrappedKey: new Uint8Array([1]),
        invocationSigner
      })
      expect(result).toEqual(bytes)
    })

    it('maps a 404 to a clear not-found error', async () => {
      postMock.mockRejectedValue(
        Object.assign(new Error('gone'), { status: 404 })
      )
      await expect(
        client.wrapKey({
          kekId: keyId,
          unwrappedKey: new Uint8Array([1]),
          invocationSigner
        })
      ).rejects.toMatchObject({
        message: 'Error wrapping key: Key encryption key not found.',
        status: 404
      })
    })
  })

  describe('unwrapKey', () => {
    it('returns the null sentinel for an explicit null unwrappedKey', async () => {
      postMock.mockResolvedValue({ data: { unwrappedKey: null } })
      const result = await client.unwrapKey({
        kekId: keyId,
        wrappedKey: base64urlnopad.encode(new Uint8Array([1])),
        invocationSigner
      })
      expect(result).toBeNull()
    })

    it('throws a clear error when unwrappedKey is missing', async () => {
      postMock.mockResolvedValue({ data: {} })
      await expect(
        client.unwrapKey({
          kekId: keyId,
          wrappedKey: base64urlnopad.encode(new Uint8Array([1])),
          invocationSigner
        })
      ).rejects.toThrow(
        'Invalid WebKMS server response: missing "unwrappedKey".'
      )
    })

    it('throws a clear error when unwrappedKey is malformed', async () => {
      postMock.mockResolvedValue({ data: { unwrappedKey: '!!!not-base64' } })
      await expect(
        client.unwrapKey({
          kekId: keyId,
          wrappedKey: base64urlnopad.encode(new Uint8Array([1])),
          invocationSigner
        })
      ).rejects.toThrow(
        'Invalid WebKMS server response: "unwrappedKey" is not base64-encoded.'
      )
    })
  })

  describe('verify', () => {
    it('returns the verified boolean', async () => {
      postMock.mockResolvedValue({ data: { verified: false } })
      const result = await client.verify({
        keyId,
        data: new Uint8Array([1]),
        signature: base64urlnopad.encode(new Uint8Array([2])),
        invocationSigner
      })
      expect(result).toBe(false)
    })

    it('throws a clear error when verified is missing or non-boolean', async () => {
      postMock.mockResolvedValue({ data: {} })
      await expect(
        client.verify({
          keyId,
          data: new Uint8Array([1]),
          signature: base64urlnopad.encode(new Uint8Array([2])),
          invocationSigner
        })
      ).rejects.toThrow('Invalid WebKMS server response: missing "verified".')
    })
  })

  describe('deriveSecret', () => {
    it('decodes the secret field', async () => {
      const secret = Uint8Array.from([9, 8, 7])
      postMock.mockResolvedValue({
        data: { secret: base64urlnopad.encode(secret) }
      })
      const result = await client.deriveSecret({
        keyId,
        publicKey: { type: 'X25519KeyAgreementKey2020' },
        invocationSigner
      })
      expect(result).toEqual(secret)
    })
  })

  describe('generateKey', () => {
    it('returns the keyId and keyDescription', async () => {
      const keyDescription = { id: keyId, type: 'Sha256HmacKey2019' }
      postMock.mockResolvedValue({ data: { keyId, keyDescription } })
      const client2 = new KmsClient({ keystoreId })
      const result = await client2.generateKey({
        type: 'Sha256HmacKey2019',
        invocationSigner
      })
      expect(result).toEqual({ keyId, keyDescription })
      expect(postMock).toHaveBeenCalledWith(
        `${keystoreId}/keys`,
        expect.anything()
      )
    })

    it('throws a clear error on a malformed response', async () => {
      postMock.mockResolvedValue({ data: {} })
      const client2 = new KmsClient({ keystoreId })
      await expect(
        client2.generateKey({ type: 'Sha256HmacKey2019', invocationSigner })
      ).rejects.toThrow(
        'Invalid WebKMS server response: missing "keyId" or "keyDescription".'
      )
    })

    it('rejects a non-integer maxCapabilityChainLength', async () => {
      const client2 = new KmsClient({ keystoreId })
      await expect(
        client2.generateKey({
          type: 'Sha256HmacKey2019',
          invocationSigner,
          maxCapabilityChainLength: 3.5
        })
      ).rejects.toThrow(
        '"maxCapabilityChainLength" must be an integer between 1 and 10.'
      )
      expect(postMock).not.toHaveBeenCalled()
    })

    it('maps a 409 to a DuplicateError cause', async () => {
      postMock.mockRejectedValue(
        Object.assign(new Error('conflict'), { status: 409 })
      )
      const client2 = new KmsClient({ keystoreId })
      let error: any
      try {
        await client2.generateKey({
          type: 'Sha256HmacKey2019',
          invocationSigner
        })
      } catch (e) {
        error = e
      }
      expect(error.message).toBe('WebKMS client error: Error generating key.')
      expect(error.cause.name).toBe('DuplicateError')
    })
  })

  describe('getKeyDescription', () => {
    it('targets the key URL on the keyId-only path', async () => {
      const keyDescription = { id: keyId, type: 'Sha256HmacKey2019' }
      getMock.mockResolvedValue({ data: keyDescription })
      const result = await client.getKeyDescription({
        keyId,
        invocationSigner,
        useCache: false
      })
      expect(result).toEqual(keyDescription)
      // the invocation is signed for -- and sent to -- the key's URL
      expect(signInvocationMock).toHaveBeenCalledWith(
        expect.objectContaining({ url: keyId })
      )
      expect(getMock).toHaveBeenCalledWith(keyId, expect.anything())
    })
  })
})
