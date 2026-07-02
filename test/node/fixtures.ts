/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */

export const keystoreId = 'https://kms.example.com/kms/keystores/z1'
export const keyId = `${keystoreId}/keys/z2`
export const invocationSigner = {
  id: 'did:key:z6MkTest#z6MkTest',
  sign: async () => new Uint8Array(64)
}
