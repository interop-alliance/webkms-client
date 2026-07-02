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
