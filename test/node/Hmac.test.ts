/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import { describe, it, expect, vi } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { Hmac } from '../../src/index.js'
import type { KmsClient } from '../../src/index.js'
import { invocationSigner, keyId } from './fixtures.js'

function createHmac({
  id = keyId,
  kmsId,
  sign = vi.fn(async () => new Uint8Array([9])),
  verify = vi.fn(async () => true)
}: {
  id?: string
  kmsId?: string
  sign?: ReturnType<typeof vi.fn>
  verify?: ReturnType<typeof vi.fn>
} = {}) {
  const kmsClient = { sign, verify } as unknown as KmsClient
  const hmac = new Hmac({
    id,
    kmsId,
    type: 'Sha256HmacKey2019',
    invocationSigner,
    kmsClient
  })
  return { hmac, sign, verify }
}

describe('Hmac', () => {
  describe('verify cache', () => {
    it('does not reuse a cached result for a different signature', async () => {
      const verify = vi.fn(
        async ({ signature }: { signature: string }) => signature === 'valid'
      )
      const { hmac } = createHmac({ verify })
      const data = new Uint8Array([1, 2, 3])

      expect(await hmac.verify({ data, signature: 'valid' })).toBe(true)
      // same data, forged signature: must hit the KMS again, not the cache
      expect(await hmac.verify({ data, signature: 'forged' })).toBe(false)
      // and a valid signature after a failed one must still verify
      expect(await hmac.verify({ data, signature: 'valid' })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(2)
    })

    it('reuses a cached result for the same data and signature', async () => {
      const { hmac, verify } = createHmac()
      const data = new Uint8Array([1, 2, 3])

      expect(await hmac.verify({ data, signature: 'sig' })).toBe(true)
      expect(await hmac.verify({ data, signature: 'sig' })).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
    })

    it('does not collide keys across the (data, signature) boundary', async () => {
      const verify = vi.fn(async () => true)
      const { hmac } = createHmac({ verify })

      // both pairs concatenate to the same string when joined naively with
      // '-' (a base64url alphabet character); each must hit the KMS
      await hmac.verify({
        data: base64urlnopad.decode('-w'),
        signature: 'X-YZ'
      })
      await hmac.verify({
        data: base64urlnopad.decode('-w-X'),
        signature: 'YZ'
      })
      expect(verify).toHaveBeenCalledTimes(2)
    })

    it('caches Uint8Array and string forms of the same signature together', async () => {
      const { hmac, verify } = createHmac()
      const data = new Uint8Array([1, 2, 3])
      // 'AQID' is base64urlnopad of [1, 2, 3]
      expect(await hmac.verify({ data, signature: 'AQID' })).toBe(true)
      expect(
        await hmac.verify({ data, signature: new Uint8Array([1, 2, 3]) })
      ).toBe(true)
      expect(verify).toHaveBeenCalledTimes(1)
    })
  })

  describe('sign cache', () => {
    it('reuses a cached signature for the same data', async () => {
      const { hmac, sign } = createHmac()
      const data = new Uint8Array([1, 2, 3])

      await hmac.sign({ data })
      await hmac.sign({ data })
      expect(sign).toHaveBeenCalledTimes(1)
    })
  })

  describe('KMS invocation target', () => {
    it('invokes the KMS with kmsId, not the public id', async () => {
      const { hmac, sign, verify } = createHmac({
        id: 'https://public.example/alias',
        kmsId: keyId
      })
      const data = new Uint8Array([1, 2, 3])

      await hmac.sign({ data, useCache: false })
      expect(sign).toHaveBeenCalledWith(expect.objectContaining({ keyId }))
      await hmac.verify({ data, signature: 'sig', useCache: false })
      expect(verify).toHaveBeenCalledWith(expect.objectContaining({ keyId }))
    })
  })
})
