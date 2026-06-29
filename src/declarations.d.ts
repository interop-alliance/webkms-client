/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
// Minimal ambient type shims for runtime dependencies that ship no types.
// These keep the conversion compiling and survive into Phase 4/7 (strict).

declare module 'base64url-universal' {
  export function encode(data: Uint8Array): string
  export function decode(data: string): Uint8Array
}

declare module '@digitalbazaar/ed25519-verification-key-2020' {
  export class Ed25519VerificationKey2020 {
    type: string
    static generate(options?: {
      seed?: Uint8Array
    }): Promise<Ed25519VerificationKey2020>
    signer(): any
    fingerprint(): string
  }
}

declare module '@digitalbazaar/http-client' {
  export const DEFAULT_HEADERS: Record<string, string>
  export const httpClient: {
    post(url: any, options?: any): Promise<{ data: any }>
    get(url: any, options?: any): Promise<{ data: any }>
  }
}

declare module '@digitalbazaar/http-signature-zcap-invoke' {
  export function signCapabilityInvocation(
    options: any
  ): Promise<Record<string, string>>
}

declare module '@digitalbazaar/lru-memoize' {
  export class LruCache {
    constructor(options?: any)
    cache: any
    memoize(options: { key: string; fn: () => any }): any
  }
}
