/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  AsymmetricKey,
  Hmac,
  Kek,
  KeyAgreementKey,
  KeystoreAgent
} from '../../src/index.js'
import type {
  CapabilityAgent,
  KeyDescription,
  KmsClient
} from '../../src/index.js'

const keystoreId = 'https://kms.example.com/kms/keystores/z1'
const keyId = `${keystoreId}/keys/z2`
const invocationSigner = {
  id: 'did:key:z6MkTest#z6MkTest',
  sign: async () => new Uint8Array(64)
}

function createAgent({ keyDescription }: { keyDescription: KeyDescription }) {
  const generateKey = vi.fn(async () => ({ keyId, keyDescription }))
  const kmsClient = { generateKey } as unknown as KmsClient
  const capabilityAgent = {
    getSigner: () => invocationSigner
  } as unknown as CapabilityAgent
  const agent = new KeystoreAgent({ capabilityAgent, keystoreId, kmsClient })
  return { agent, generateKey }
}

describe('KeystoreAgent.generateKey', () => {
  it('resolves the recommended key type from `category` alone', async () => {
    const { agent, generateKey } = createAgent({
      keyDescription: { id: keyId, type: 'AesKeyWrappingKey2019' }
    })
    const key = await agent.generateKey({ category: 'kek' })
    expect(key).toBeInstanceOf(Kek)
    expect(generateKey).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'AesKeyWrappingKey2019' })
    )
  })

  it('resolves an hmac category', async () => {
    const { agent, generateKey } = createAgent({
      keyDescription: { id: keyId, type: 'Sha256HmacKey2019' }
    })
    const key = await agent.generateKey({ category: 'hmac' })
    expect(key).toBeInstanceOf(Hmac)
    expect(generateKey).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'Sha256HmacKey2019' })
    )
  })

  it('resolves a keyAgreement category', async () => {
    const { agent } = createAgent({
      keyDescription: { id: keyId, type: 'X25519KeyAgreementKey2020' }
    })
    const key = await agent.generateKey({ category: 'keyAgreement' })
    expect(key).toBeInstanceOf(KeyAgreementKey)
  })

  it('still accepts a category name passed as `type` (deprecated)', async () => {
    const { agent, generateKey } = createAgent({
      keyDescription: {
        id: 'did:key:z6MkTest',
        type: 'Ed25519VerificationKey2020',
        publicKeyMultibase: 'z6MkTest'
      }
    })
    const key = await agent.generateKey({ type: 'asymmetric' })
    expect(key).toBeInstanceOf(AsymmetricKey)
    expect(generateKey).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'Ed25519VerificationKey2020' })
    )
  })

  it('accepts a custom key type URL together with a category', async () => {
    const { agent, generateKey } = createAgent({
      keyDescription: {
        id: 'did:key:zDnaTest',
        type: 'Multikey',
        publicKeyMultibase: 'zDnaTest'
      }
    })
    const key = await agent.generateKey({
      category: 'asymmetric',
      type: 'urn:webkms:multikey:P-256'
    })
    expect(key).toBeInstanceOf(AsymmetricKey)
    expect(generateKey).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'urn:webkms:multikey:P-256' })
    )
    expect(key.kmsId).toBe(keyId)
  })

  it('rejects a custom key type URL without a category', async () => {
    const { agent } = createAgent({
      keyDescription: { id: keyId, type: 'Multikey' }
    })
    await expect(
      agent.generateKey({ type: 'urn:webkms:multikey:P-256' })
    ).rejects.toThrow(
      '"category" is required when a custom key "type" is given.'
    )
  })

  it('rejects a call with neither category nor type', async () => {
    const { agent } = createAgent({
      keyDescription: { id: keyId, type: 'Sha256HmacKey2019' }
    })
    await expect(agent.generateKey()).rejects.toThrow(
      'Either "category" or "type" is required.'
    )
  })

  it('rejects an unknown category', async () => {
    const { agent } = createAgent({
      keyDescription: { id: keyId, type: 'Sha256HmacKey2019' }
    })
    await expect(agent.generateKey({ category: 'sekrit' })).rejects.toThrow(
      'Unknown key category "sekrit".'
    )
  })

  it('attributes a construction failure to the already-created key', async () => {
    // the server created the key but returned a type the Hmac class does
    // not recognize; the error must say the key exists server-side
    const { agent } = createAgent({
      keyDescription: { id: keyId, type: 'NotARealHmacType' }
    })
    let error: any
    try {
      await agent.generateKey({ category: 'hmac' })
    } catch (e) {
      error = e
    }
    expect(error.message).toContain(
      `Generated key "${keyId}" exists in the keystore`
    )
    expect(error.cause.message).toContain('Unknown key type')
  })
})
