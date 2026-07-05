/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { base64urlnopad } from '@scure/base'
import type { IZcap } from '@interop/data-integrity-core'

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
import { invocationSigner, keyId, keystoreId } from './fixtures.js'

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

  describe('invocation target scheme policy', () => {
    it('refuses an http keyId on a non-loopback host', async () => {
      await expect(
        client.sign({
          keyId: 'http://any.host/kms/keystores/z1/keys/z2',
          data: new Uint8Array([1]),
          invocationSigner
        })
      ).rejects.toThrow('must be an "https" URL')
      expect(postMock).not.toHaveBeenCalled()
    })

    it('allows an http keyId on a loopback host by default', async () => {
      postMock.mockResolvedValue({ data: { verified: true } })
      const result = await client.verify({
        keyId: 'http://localhost:3002/kms/keystores/z1/keys/z2',
        data: new Uint8Array([1]),
        signature: 'AQID',
        invocationSigner
      })
      expect(result).toBe(true)
    })

    it('refuses http loopback when allowInsecureLoopback is false', async () => {
      const strictClient = new KmsClient({ allowInsecureLoopback: false })
      await expect(
        strictClient.sign({
          keyId: 'http://localhost:3002/kms/keystores/z1/keys/z2',
          data: new Uint8Array([1]),
          invocationSigner
        })
      ).rejects.toThrow('must be an "https" URL.')
      expect(postMock).not.toHaveBeenCalled()
    })
  })

  describe('getKeystore', () => {
    it('throws a clear error on a non-object response body', async () => {
      getMock.mockResolvedValue({ data: '<html>proxy error</html>' })
      const client2 = new KmsClient({ keystoreId })
      await expect(client2.getKeystore({ invocationSigner })).rejects.toThrow(
        'Invalid WebKMS server response: expected an object body.'
      )
    })
  })

  describe('createKeystore', () => {
    it('maps a 409 to a DuplicateError cause', async () => {
      postMock.mockRejectedValue(
        Object.assign(new Error('conflict'), { status: 409 })
      )
      let error: any
      try {
        await KmsClient.createKeystore({
          url: 'https://kms.example.com/kms/keystores',
          config: { controller: 'did:key:z6MkTest' },
          invocationSigner
        })
      } catch (e) {
        error = e
      }
      expect(error.message).toBe(
        'WebKMS client error: Error during "create keystore" operation.'
      )
      expect(error.cause.name).toBe('DuplicateError')
    })

    it('throws a clear error when the returned config is missing "id"', async () => {
      postMock.mockResolvedValue({ data: {} })
      await expect(
        KmsClient.createKeystore({
          url: 'https://kms.example.com/kms/keystores',
          config: { controller: 'did:key:z6MkTest' },
          invocationSigner
        })
      ).rejects.toThrow(
        'Invalid WebKMS server response: missing keystore "id".'
      )
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

  describe('listKeys', () => {
    const d1 = { id: `${keyId}`, type: 'Multikey', publicKeyMultibase: 'z1' }
    const d2 = { id: `${keystoreId}/keys/z3`, type: 'Multikey' }

    it('returns a single page and targets <keystoreId>/keys with read', async () => {
      getMock.mockResolvedValue({ data: { results: [d1, d2] } })
      const client2 = new KmsClient({ keystoreId })
      const result = await client2.listKeys({ invocationSigner })
      expect(result).toEqual([d1, d2])
      expect(getMock).toHaveBeenCalledWith(
        `${keystoreId}/keys`,
        expect.anything()
      )
      expect(signInvocationMock).toHaveBeenCalledWith(
        expect.objectContaining({
          url: `${keystoreId}/keys`,
          capabilityAction: 'read'
        })
      )
    })

    it('returns an empty array for an empty keystore', async () => {
      getMock.mockResolvedValue({ data: { results: [] } })
      const client2 = new KmsClient({ keystoreId })
      await expect(client2.listKeys({ invocationSigner })).resolves.toEqual([])
    })

    it('auto-follows the "next" cursor to exhaustion', async () => {
      getMock
        .mockResolvedValueOnce({
          data: { results: [d1], next: '/kms/keystores/z1/keys?cursor=abc' }
        })
        .mockResolvedValueOnce({ data: { results: [d2] } })
      const client2 = new KmsClient({ keystoreId })
      const result = await client2.listKeys({ invocationSigner })
      expect(result).toEqual([d1, d2])
      // the origin-relative cursor resolves against the keystore origin
      expect(getMock).toHaveBeenNthCalledWith(
        2,
        'https://kms.example.com/kms/keystores/z1/keys?cursor=abc',
        expect.anything()
      )
    })

    it('uses a delegated capability for every page', async () => {
      const capability = {
        id: 'urn:zcap:delegated:z9',
        invocationTarget: `${keystoreId}/keys`
      } as IZcap
      getMock
        .mockResolvedValueOnce({
          data: { results: [d1], next: '/kms/keystores/z1/keys?cursor=abc' }
        })
        .mockResolvedValueOnce({ data: { results: [d2] } })
      const result = await client.listKeys({ capability, invocationSigner })
      expect(result).toEqual([d1, d2])
      expect(getMock).toHaveBeenCalledWith(
        `${keystoreId}/keys`,
        expect.anything()
      )
      // the same delegated capability is passed to the signer on each page
      expect(signInvocationMock).toHaveBeenCalledTimes(2)
      expect(signInvocationMock).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({ capability })
      )
      expect(signInvocationMock).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({ capability })
      )
    })

    it('rejects a response missing the "results" array', async () => {
      getMock.mockResolvedValue({ data: {} })
      const client2 = new KmsClient({ keystoreId })
      await expect(client2.listKeys({ invocationSigner })).rejects.toThrow(
        'Invalid WebKMS server response: missing "results".'
      )
    })

    it('rejects a non-string "next"', async () => {
      getMock.mockResolvedValue({ data: { results: [], next: 5 } })
      const client2 = new KmsClient({ keystoreId })
      await expect(client2.listKeys({ invocationSigner })).rejects.toThrow(
        'Invalid WebKMS server response: "next" must be a string.'
      )
    })

    it('refuses a cross-origin "next"', async () => {
      getMock.mockResolvedValue({
        data: {
          results: [d1],
          next: 'https://evil.example/kms/keystores/z1/keys?cursor=x'
        }
      })
      const client2 = new KmsClient({ keystoreId })
      await expect(client2.listKeys({ invocationSigner })).rejects.toThrow(
        /cross-origin/
      )
    })

    it('enforces the maxPages guard', async () => {
      let cursor = 0
      getMock.mockImplementation(async () => ({
        data: {
          results: [d1],
          next: `/kms/keystores/z1/keys?cursor=${cursor++}`
        }
      }))
      const client2 = new KmsClient({ keystoreId })
      await expect(
        client2.listKeys({ invocationSigner, maxPages: 3 })
      ).rejects.toThrow(/more than 3/)
      expect(getMock).toHaveBeenCalledTimes(3)
    })

    it('maps a 404 to a clear not-found error', async () => {
      getMock.mockRejectedValue(
        Object.assign(new Error('gone'), { status: 404 })
      )
      const client2 = new KmsClient({ keystoreId })
      await expect(
        client2.listKeys({ invocationSigner })
      ).rejects.toMatchObject({
        message: 'Error listing keys: Keystore not found.',
        status: 404
      })
    })

    it('requires a keystoreId or capability', async () => {
      await expect(client.listKeys({ invocationSigner })).rejects.toThrow(
        /capability.*required/
      )
      expect(getMock).not.toHaveBeenCalled()
    })
  })
})
