/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import { describe, it, expect } from 'vitest'
import * as kmsClient from '../../src/index.js'

describe('webkms-client API', () => {
  it('should have proper exports', async () => {
    expect(kmsClient).toBeDefined()
    expect(kmsClient.AsymmetricKey).toBeDefined()
    expect(kmsClient.CapabilityAgent).toBeDefined()
    expect(kmsClient.Hmac).toBeDefined()
    expect(kmsClient.Kek).toBeDefined()
    expect(kmsClient.KeyAgreementKey).toBeDefined()
    expect(kmsClient.KeystoreAgent).toBeDefined()
    expect(kmsClient.KmsClient).toBeDefined()
  })
})
