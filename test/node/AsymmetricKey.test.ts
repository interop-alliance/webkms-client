/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import { AsymmetricKey } from '../../src/index.js'

const keys = new Map([
  [
    'Bls12381G2',
    'did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ'
  ],
  ['Ed25519', 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'],
  ['P-256', 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169'],
  [
    'P-384',
    'did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcV' +
      'BgjGhnLBn2Kaau9'
  ],
  [
    'P-521',
    'did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7S' +
      'zcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7'
  ],
  ['secp256k1', 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme']
])

describe('AsymmetricKey API', () => {
  describe('getAlgorithm', () => {
    it('returns undefined when called without a key description', () => {
      expect(AsymmetricKey.getAlgorithm()).toBeUndefined()
      expect(AsymmetricKey.getAlgorithm({})).toBeUndefined()
      expect(AsymmetricKey.getAlgorithm({ keyDescription: {} })).toBeUndefined()
    })
  })

  describe('getKeyDescription', () => {
    it('returns a clone of the cached key description', async () => {
      const keyDescription = {
        id: 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g',
        type: 'Ed25519VerificationKey2020',
        publicKeyMultibase: 'z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'
      }
      const key = new AsymmetricKey({ keyDescription })
      const result = await key.getKeyDescription()
      expect(result).toEqual(keyDescription)
      expect(result).not.toBe(keyDescription)
      // mutating the returned clone must not affect the cached copy
      result.type = 'mutated'
      expect((await key.getKeyDescription()).type).toBe(
        'Ed25519VerificationKey2020'
      )
    })
  })

  describe('should create key from keyDescription', () => {
    for (const [keyType, did] of keys) {
      it(`key type ${keyType}`, async () => {
        const keyDescription = {
          id: did,
          type: keyType,
          publicKeyMultibase: did.slice(8)
        }
        const key = new AsymmetricKey({ keyDescription })
        expect(key, 'Expected a key to exist').toBeDefined()
        expect(key.algorithm, 'Expected "key.algorithm" to exist').toBeDefined()
        expect(typeof key.algorithm).toBe('string')
        expect(key.algorithm, `Expected "key.algorithm" to be ${keyType}`).toBe(
          keyType
        )
      })
    }
  })
})
