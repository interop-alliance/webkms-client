/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import { describe, it, expect, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { AsymmetricKey, Hmac, Kek, KeyAgreementKey } from '../../src/index.js'
import type { KeyDescription, KmsClient } from '../../src/index.js'
import { invocationSigner, keyId as invocationTarget } from './fixtures.js'

// minimal delegated zcap stub; only the fields the client reads
const capability = {
  id: 'urn:uuid:delegated-zcap',
  invocationTarget
} as IZcap

function createKmsClient(keyDescription: KeyDescription) {
  return {
    getKeyDescription: vi.fn(async () => keyDescription)
  } as unknown as KmsClient
}

describe('key classes fromCapability', () => {
  it('builds an Hmac from a capability', async () => {
    const kmsClient = createKmsClient({
      id: invocationTarget,
      type: 'Sha256HmacKey2019'
    })
    const key = await Hmac.fromCapability({
      capability,
      invocationSigner,
      kmsClient
    })
    expect(key).toBeInstanceOf(Hmac)
    expect(key.id).toBe(invocationTarget)
    expect(key.kmsId).toBe(invocationTarget)
    expect(key.algorithm).toBe('HS256')
    expect(key.capability).toBe(capability)
  })

  it('builds a Kek from a capability', async () => {
    const kmsClient = createKmsClient({
      id: invocationTarget,
      type: 'AesKeyWrappingKey2019'
    })
    const key = await Kek.fromCapability({
      capability,
      invocationSigner,
      kmsClient
    })
    expect(key).toBeInstanceOf(Kek)
    expect(key.id).toBe(invocationTarget)
    expect(key.kmsId).toBe(invocationTarget)
    expect(key.algorithm).toBe('A256KW')
    expect(key.capability).toBe(capability)
  })

  it('builds an AsymmetricKey from a capability', async () => {
    const publicId = 'did:key:z6MkTest#z6MkTest'
    const kmsClient = createKmsClient({
      id: publicId,
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6MkTest'
    })
    const key = await AsymmetricKey.fromCapability({
      capability,
      invocationSigner,
      kmsClient
    })
    expect(key).toBeInstanceOf(AsymmetricKey)
    // the public ID comes from the key description; the KMS ID is the
    // capability's invocation target
    expect(key.id).toBe(publicId)
    expect(key.kmsId).toBe(invocationTarget)
    expect(key.algorithm).toBe('Ed25519')
    expect(key.capability).toBe(capability)
  })

  it('builds a KeyAgreementKey from a capability', async () => {
    const publicId = 'did:key:z6LSTest#z6LSTest'
    const kmsClient = createKmsClient({
      id: publicId,
      type: 'X25519KeyAgreementKey2020'
    })
    const key = await KeyAgreementKey.fromCapability({
      capability,
      invocationSigner,
      kmsClient
    })
    expect(key).toBeInstanceOf(KeyAgreementKey)
    expect(key.id).toBe(publicId)
    expect(key.kmsId).toBe(invocationTarget)
    expect(key.type).toBe('X25519KeyAgreementKey2020')
    expect(key.capability).toBe(capability)
  })

  it('requires a capability', async () => {
    const kmsClient = createKmsClient({
      id: invocationTarget,
      type: 'Sha256HmacKey2019'
    })
    await expect(
      Hmac.fromCapability({ invocationSigner, kmsClient })
    ).rejects.toThrow('"capability" is required.')
  })
})

describe('key class constructors', () => {
  it('reject a capability passed to the constructor', () => {
    for (const construct of [
      () =>
        new Hmac({
          id: invocationTarget,
          type: 'Sha256HmacKey2019',
          capability
        }),
      () =>
        new Kek({
          id: invocationTarget,
          type: 'AesKeyWrappingKey2019',
          capability
        }),
      () => new AsymmetricKey({ id: invocationTarget, capability }),
      () => new KeyAgreementKey({ id: invocationTarget, capability })
    ]) {
      expect(construct).toThrow(
        '"capability" parameter not allowed in constructor'
      )
    }
  })
})

describe('Kek KMS invocation target', () => {
  it('invokes the KMS with kmsId, not the public id', async () => {
    const wrapKey = vi.fn(async () => new Uint8Array([1]))
    const unwrapKey = vi.fn(async () => new Uint8Array([2]))
    const kmsClient = { wrapKey, unwrapKey } as unknown as KmsClient
    const kek = new Kek({
      id: 'https://public.example/alias',
      kmsId: invocationTarget,
      type: 'AesKeyWrappingKey2019',
      invocationSigner,
      kmsClient
    })

    await kek.wrapKey({ unwrappedKey: new Uint8Array([3]) })
    expect(wrapKey).toHaveBeenCalledWith(
      expect.objectContaining({ kekId: invocationTarget })
    )
    await kek.unwrapKey({ wrappedKey: 'AQID' })
    expect(unwrapKey).toHaveBeenCalledWith(
      expect.objectContaining({ kekId: invocationTarget })
    )
  })
})
