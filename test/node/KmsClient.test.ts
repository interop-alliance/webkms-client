/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import type { IZcap } from '@interop/data-integrity-core'
import { describe, it, expect } from 'vitest'
import { KmsClient } from '../../src/index.js'

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:'

describe('KmsClient._getInvocationTarget', () => {
  it('accepts an https invocation target (object capability)', () => {
    const invocationTarget = 'https://kms.example.com/kms/keystores/z123'
    expect(
      KmsClient._getInvocationTarget({
        capability: { invocationTarget } as IZcap
      })
    ).toBe(invocationTarget)
  })

  it('accepts an https invocation target (root capability string)', () => {
    const invocationTarget = 'https://kms.example.com/kms/keystores/z123'
    const capability = ZCAP_ROOT_PREFIX + encodeURIComponent(invocationTarget)
    expect(KmsClient._getInvocationTarget({ capability })).toBe(
      invocationTarget
    )
  })

  it('accepts http loopback targets (development exception)', () => {
    for (const invocationTarget of [
      'http://localhost:3002/kms/keystores/z123',
      'http://127.0.0.1:3002/kms/keystores/z123',
      'http://[::1]:3002/kms/keystores/z123'
    ]) {
      expect(
        KmsClient._getInvocationTarget({
          capability: { invocationTarget } as IZcap
        })
      ).toBe(invocationTarget)
    }
  })

  it('rejects http targets on non-loopback hosts', () => {
    for (const invocationTarget of [
      'http://kms.example.com/kms/keystores/z123',
      'http://192.0.2.10:3002/kms/keystores/z123',
      // no scheme-relative or lookalike bypasses
      'http://localhost.example.com/kms/keystores/z123'
    ]) {
      expect(() =>
        KmsClient._getInvocationTarget({
          capability: { invocationTarget } as IZcap
        })
      ).toThrow(TypeError)
    }
  })

  it('rejects non-http(s) and malformed targets', () => {
    for (const invocationTarget of [
      'ftp://localhost/kms',
      'http://',
      'not-a-url'
    ]) {
      expect(() =>
        KmsClient._getInvocationTarget({
          capability: { invocationTarget } as IZcap
        })
      ).toThrow(TypeError)
    }
  })
})
