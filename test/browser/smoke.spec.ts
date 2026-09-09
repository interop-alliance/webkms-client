/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import { test, expect } from '@playwright/test'

// Smoke test: prove the bundle loads in a real browser and its core classes
// construct without a KMS server.
test('webkms-client loads in the browser', async ({ page }) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // This callback runs in the browser; '/src/index.ts' is a URL served by the
    // vite dev server, not a module path tsc can resolve from disk.
    // @ts-expect-error -- dev-server URL, resolved at runtime by vite
    const { AsymmetricKey, KmsClient } = await import('/src/index.ts')
    const key = new AsymmetricKey({
      keyDescription: {
        id: 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g',
        type: 'Ed25519',
        publicKeyMultibase: 'z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'
      }
    })
    const client = new KmsClient({
      keystoreId: 'https://kms.example/keystores/z1'
    })
    return { algorithm: key.algorithm, keystoreId: client.keystoreId }
  })
  expect(result.algorithm).toBe('Ed25519')
  expect(result.keystoreId).toBe('https://kms.example/keystores/z1')
})
