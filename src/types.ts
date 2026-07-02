/*!
 * Copyright (c) 2026 Interop Alliance and Dmitri Zagidulin.
 */

/**
 * An API for signing capability invocations (e.g. a `did:key` signer as
 * returned by `CapabilityAgent.getSigner()`).
 */
export interface InvocationSigner {
  /** The ID of the signing key (a verification method URI). */
  id: string
  /** The key type (e.g. `Ed25519VerificationKey2020`). */
  type?: string
  /** Signs the given data, resolving to the signature bytes. */
  sign(options: { data: Uint8Array }): Promise<Uint8Array>
}

/**
 * An authorization capability (zcap): either a root capability ID string
 * (`urn:zcap:root:<encodeURIComponent(invocationTarget)>`) or a capability
 * object. Objects are typed loosely -- only the fields this client reads --
 * so zcaps produced by other libraries can be passed as-is.
 */
export type Capability =
  | string
  | {
      /** The capability ID (an absolute URI). */
      id?: string
      /** The resource URI this capability grants access to. */
      invocationTarget?: string
      /** The parent capability ID (present on delegated zcaps). */
      parentCapability?: string
      [key: string]: unknown
    }

/**
 * A WebKMS key description, as returned by a KMS server.
 */
export interface KeyDescription {
  '@context'?: string | string[]
  /** The (public) key ID. */
  id?: string
  /** The key type (e.g. `Ed25519VerificationKey2020`). */
  type?: string
  /** The multibase-encoded public key, for asymmetric keys. */
  publicKeyMultibase?: string
  [key: string]: unknown
}

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
