/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */
import type {
  IPublicKey2020,
  IPublicMultikey
} from '@interop/data-integrity-core'

/**
 * A key description (public key document) as returned by a WebKMS server.
 */
export type KeyDescription = IPublicKey2020 | IPublicMultikey

/**
 * A List Keys entry: the Get Key Description projection plus `keyUrl`, the
 * key's canonical invocation URL (`<keystoreId>/keys/<localId>`). Stamped by
 * the server on every listed entry because a `publicAlias` /
 * `publicAliasTemplate` override rewrites the description's `id`, erasing
 * exactly the signable handle a recovery client lists keys to rediscover.
 * When no alias is set, `keyUrl` duplicates `id`.
 */
export type ListedKeyDescription = KeyDescription & { keyUrl: string }

/**
 * A WebKMS keystore configuration.
 */
export interface KeystoreConfig {
  /** The keystore ID (a URL); assigned by the server on creation. */
  id?: string
  /** The DID of the keystore's controller. */
  controller?: string
  /** The configuration sequence number. */
  sequence?: number
  [key: string]: unknown
}
