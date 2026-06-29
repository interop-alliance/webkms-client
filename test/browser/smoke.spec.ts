/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import { test, expect } from '@playwright/test'

// Smoke test: prove the bundle loads in a real browser and a core API path
// works. `CapabilityAgent.fromSecret` drives `globalThis.crypto.subtle`
// (digest + importKey + sign), exercising the WebCrypto path in the browser.
test('webkms-client loads in the browser and uses webcrypto', async ({
  page
}) => {
  await page.goto('/test/index.html')
  const result = await page.evaluate(async () => {
    // This callback runs in the browser; '/src/index.ts' is a URL served by the
    // vite dev server, not a module path tsc can resolve from disk.
    // @ts-expect-error -- dev-server URL, resolved at runtime by vite
    const { CapabilityAgent, AsymmetricKey } = await import('/src/index.ts')
    // exercises the browser crypto path (globalThis.crypto.subtle)
    const agent = await CapabilityAgent.fromSecret({
      secret: 'smoke-test-secret',
      handle: 'smoke-test-handle'
    })
    // core API path that does not require crypto.subtle
    const key = new AsymmetricKey({
      keyDescription: {
        id: 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g',
        type: 'Ed25519',
        publicKeyMultibase: 'z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'
      }
    })
    return {
      agentId: agent.id,
      hasSigner: Boolean(agent.getSigner()),
      algorithm: key.algorithm
    }
  })
  expect(result.agentId).toMatch(/^did:key:/)
  expect(result.hasSigner).toBe(true)
  expect(result.algorithm).toBe('Ed25519')
})
