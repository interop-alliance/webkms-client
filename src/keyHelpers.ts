/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import type { ISigner, IZcap } from '@interop/data-integrity-core'
import { KmsClient } from './KmsClient.js'
import type { KeyDescription } from './types.js'

/**
 * Throws if a `capability` was passed to a key class constructor; key
 * instances bound to a capability must be created via `.fromCapability`.
 *
 * @param {object|string} [capability] - The offending constructor argument.
 */
export function assertNoCapability(capability?: IZcap | string): void {
  if (capability) {
    throw new Error(
      '"capability" parameter not allowed in constructor; ' +
        'use ".fromCapability" instead.'
    )
  }
}

/**
 * Shared implementation for the key classes' `.fromCapability` factories:
 * fetches the key description via the capability, then constructs the given
 * key class using the description's `id`/`type` (falling back to the
 * capability's invocation target as `id`) and the capability's invocation
 * target as the key's ID with the KMS.
 *
 * @param {object} options - The options to use.
 * @param {Function} options.KeyClass - The key class to construct.
 * @param {object|string} options.capability - The authorization capability.
 * @param {object} options.invocationSigner - An API for signing a capability
 *   invocation.
 * @param {KmsClient} options.kmsClient - The KmsClient to use.
 *
 * @returns {Promise<object>} The new key instance.
 */
export async function fromCapability<
  T extends { capability?: IZcap | string }
>({
  KeyClass,
  capability,
  invocationSigner,
  kmsClient
}: {
  KeyClass: new (options: {
    id?: string
    kmsId?: string
    type?: string
    invocationSigner?: ISigner
    kmsClient?: KmsClient
    keyDescription?: KeyDescription
  }) => T
  capability?: IZcap | string
  invocationSigner?: ISigner
  kmsClient: KmsClient
}): Promise<T> {
  if (!capability) {
    throw new TypeError('"capability" is required.')
  }

  // get key description via capability
  const keyDescription = await kmsClient.getKeyDescription({
    capability,
    invocationSigner
  })

  // build the key from its description; the capability's invocation target
  // is the key's ID with the KMS (and its public ID, absent a public alias)
  const kmsId = KmsClient._getInvocationTarget({ capability })
  const { id = kmsId, type } = keyDescription
  const key = new KeyClass({
    id,
    kmsId,
    type,
    kmsClient,
    invocationSigner,
    keyDescription
  })
  key.capability = capability
  return key
}
