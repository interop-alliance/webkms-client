/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import { CapabilityAgent } from '../../src/index.js'

describe('CapabilityAgent.fromSecret', () => {
  describe('string secrets (behavior must not change)', () => {
    // Golden did:key values captured from the implementation BEFORE the binary
    // secret hashing fix. String-secret derivation must remain byte-identical,
    // so these values must never change.
    const goldens: Array<
      [string, Parameters<typeof CapabilityAgent.fromSecret>[0]]
    > = [
      [
        'did:key:z6MkiS4sLV7Z3bWoV8PtgrrwDy41H2PciiWYY6jXwCc7RmHh',
        { secret: 'correct horse battery staple', handle: 'urn:example:alice' }
      ],
      [
        'did:key:z6MkkoLvN3jJZhKuSz8o7y1Tjauti8xRB7o5v3z9zV4e3h8r',
        {
          secret: 'correct horse battery staple',
          handle: 'urn:example:alice',
          keyName: 'signing'
        }
      ],
      [
        'did:key:z6MkfaUh2mPThm8BAApsDsb4YpiTQCJRJKRWtDBZjW4VmxW6',
        { secret: 's3cr3t', handle: 'acct:bob@example.com' }
      ]
    ]

    for (const [expectedId, options] of goldens) {
      it(`derives ${expectedId}`, async () => {
        const agent = await CapabilityAgent.fromSecret(options)
        expect(agent.id).toBe(expectedId)
      })
    }

    it('derives different keys for different keyNames', async () => {
      const a = await CapabilityAgent.fromSecret({
        secret: 'correct horse battery staple',
        handle: 'urn:example:alice'
      })
      const b = await CapabilityAgent.fromSecret({
        secret: 'correct horse battery staple',
        handle: 'urn:example:alice',
        keyName: 'signing'
      })
      expect(a.id).not.toBe(b.id)
    })
  })

  describe('binary secrets', () => {
    it('does not collapse distinct binary secrets to the same key', async () => {
      // Both 0xFF and 0xFE are invalid UTF-8; the old TextDecoder round-trip
      // collapsed both to U+FFFD and derived an identical key.
      const a = await CapabilityAgent.fromSecret({
        secret: new Uint8Array([0xff]),
        handle: 'h'
      })
      const b = await CapabilityAgent.fromSecret({
        secret: new Uint8Array([0xfe]),
        handle: 'h'
      })
      expect(a.id).toMatch(/^did:key:/)
      expect(b.id).toMatch(/^did:key:/)
      expect(a.id).not.toBe(b.id)
    })

    it('derives a stable key for the same binary secret', async () => {
      const secret = new Uint8Array([0, 1, 2, 3, 255])
      const a = await CapabilityAgent.fromSecret({ secret, handle: 'h' })
      const b = await CapabilityAgent.fromSecret({
        secret: new Uint8Array([0, 1, 2, 3, 255]),
        handle: 'h'
      })
      expect(a.id).toBe(b.id)
    })
  })

  it('rejects a non-string, non-Uint8Array secret', async () => {
    await expect(
      // @ts-expect-error -- intentionally passing an invalid secret type
      CapabilityAgent.fromSecret({ secret: 42, handle: 'h' })
    ).rejects.toThrow('"secret" must be a Uint8Array or a string.')
  })

  it('rejects a non-string handle', async () => {
    await expect(
      // @ts-expect-error -- intentionally passing an invalid handle type
      CapabilityAgent.fromSecret({ secret: 's3cr3t', handle: 42 })
    ).rejects.toThrow('"handle" must be a string.')
  })
})

describe('CapabilityAgent.seedFromSecret / fromSeed', () => {
  it('fromSeed(seedFromSecret(...)) equals fromSecret(...)', async () => {
    const options = {
      secret: 'correct horse battery staple',
      handle: 'urn:example:alice',
      keyName: 'signing'
    }
    const fromSecret = await CapabilityAgent.fromSecret(options)
    const seed = await CapabilityAgent.seedFromSecret(options)
    const fromSeed = await CapabilityAgent.fromSeed({
      seed,
      handle: options.handle,
      keyName: options.keyName
    })
    expect(fromSeed.id).toBe(fromSecret.id)
    expect(fromSeed.getVerificationKeyPair()).toEqual(
      fromSecret.getVerificationKeyPair()
    )
  })

  it('matches the golden string-secret derivation through the seed path', async () => {
    // Same golden as the fromSecret suite: proves the seed split did not
    // change the derivation.
    const seed = await CapabilityAgent.seedFromSecret({
      secret: 'correct horse battery staple',
      handle: 'urn:example:alice'
    })
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: 'urn:example:alice'
    })
    expect(agent.id).toBe(
      'did:key:z6MkiS4sLV7Z3bWoV8PtgrrwDy41H2PciiWYY6jXwCc7RmHh'
    )
  })

  it('returns a 32-byte seed', async () => {
    const seed = await CapabilityAgent.seedFromSecret({
      secret: 's3cr3t',
      handle: 'h'
    })
    expect(seed).toBeInstanceOf(Uint8Array)
    expect(seed.length).toBe(32)
  })

  it('fromSeed does NOT equal fromSecret fed the seed as a secret', async () => {
    // The two entrances are not interchangeable: fromSecret would hash the
    // seed again.
    const seed = await CapabilityAgent.seedFromSecret({
      secret: 's3cr3t',
      handle: 'h'
    })
    const viaSeed = await CapabilityAgent.fromSeed({ seed, handle: 'h' })
    const viaSecret = await CapabilityAgent.fromSecret({
      secret: seed,
      handle: 'h'
    })
    expect(viaSeed.id).not.toBe(viaSecret.id)
  })

  it('derives different keys for different keyNames from one seed', async () => {
    const seed = await CapabilityAgent.seedFromSecret({
      secret: 's3cr3t',
      handle: 'h'
    })
    const a = await CapabilityAgent.fromSeed({ seed, handle: 'h' })
    const b = await CapabilityAgent.fromSeed({
      seed,
      handle: 'h',
      keyName: 'signing'
    })
    expect(a.id).not.toBe(b.id)
  })

  it('rejects a non-Uint8Array seed', async () => {
    await expect(
      // @ts-expect-error -- intentionally passing an invalid seed type
      CapabilityAgent.fromSeed({ seed: 's3cr3t', handle: 'h' })
    ).rejects.toThrow('"seed" must be a non-empty Uint8Array.')
  })

  it('rejects an empty seed', async () => {
    await expect(
      CapabilityAgent.fromSeed({ seed: new Uint8Array(0), handle: 'h' })
    ).rejects.toThrow('"seed" must be a non-empty Uint8Array.')
  })

  it('rejects a non-string handle', async () => {
    await expect(
      CapabilityAgent.fromSeed({
        seed: new Uint8Array(32),
        // @ts-expect-error -- intentionally passing an invalid handle type
        handle: 42
      })
    ).rejects.toThrow('"handle" must be a string.')
  })
})

describe('CapabilityAgent.getVerificationKeyPair', () => {
  it('returns the signing key descriptor with controller set', async () => {
    const agent = await CapabilityAgent.fromSecret({
      secret: 'correct horse battery staple',
      handle: 'urn:example:alice'
    })
    const keyPair = agent.getVerificationKeyPair()
    const fingerprint = agent.id.slice('did:key:'.length)
    expect(keyPair).toEqual({
      id: `${agent.id}#${fingerprint}`,
      type: 'Ed25519VerificationKey2020',
      controller: agent.id,
      publicKeyMultibase: expect.stringMatching(/^z6Mk/),
      privateKeyMultibase: expect.stringMatching(/^z/)
    })
  })

  it('throws when key material is absent', () => {
    const agent = new CapabilityAgent({
      handle: 'h',
      signer: {
        id: 'did:key:z6MkExample#z6MkExample',
        sign: async () => new Uint8Array()
      },
      // @ts-expect-error -- intentionally passing a key pair without material
      keyPair: {}
    })
    expect(() => agent.getVerificationKeyPair()).toThrow(
      'CapabilityAgent is missing Ed25519 key material'
    )
  })
})
