# webkms-client ChangeLog

## 14.7.1 - TBD

### Changed

- `KmsClient.listKeys()` / `KeystoreAgent.listKeys()` now return
  `ListedKeyDescription[]` (a new exported type): the key description plus a
  required `keyUrl`, the key's canonical invocation URL
  (`<keystoreId>/keys/<localId>`), which the server stamps on every list entry
  -- the `publicAlias` / `publicAliasTemplate` override rewrites `id`, erasing
  exactly the signable handle a recovery client lists keys to rediscover.
  Type-level only: the entries always passed the field through verbatim at
  runtime. Requires a server with the list-entry `keyUrl` projection
  (was-teaching-server's K5 fix).

## 14.7.0 - 2026-07-05

### Added

- `KmsClient.listKeys()` and `KeystoreAgent.listKeys()` -- enumerate a
  keystore's public key descriptions (a fork extension beyond upstream
  webkms-switch; server: `GET <keystoreId>/keys`). Zcap-signed `read` against
  the keystore controller, auto-follows the server's `next` cursor to
  exhaustion, returns `KeyDescription[]` sorted by local id, never any secret
  field. A recovery-path operation (rediscover a lost key id, adopt orphaned
  keys); not cached.

## 14.6.0 - 2026-07-02

### Added

- `CapabilityAgent.seedFromSecret()` and `CapabilityAgent.fromSeed()` -- the two
  halves of `fromSecret()`, exposed separately: `seedFromSecret()` returns the
  32-byte salted-hash seed a secret derives to, and `fromSeed()` reconstitutes
  an agent from that seed directly (skipping the hashing step). Together they
  let a caller persist the seed (suitably encrypted) and later rebuild the same
  agent -- same key pair, same did:key id -- without the original secret.
  `fromSecret()` is now the composition of the two; its derivation is
  byte-identical to before.

## 14.5.0 - 2026-07-02

### Added

- `CapabilityAgent.getVerificationKeyPair()` -- returns the underlying Ed25519
  verification key descriptor (with `controller` set to the agent's did:key id)
  so consumers can derive related keys (e.g. an X25519 key agreement key)
  without reading the private `_keyPair` field. The descriptor is built via the
  key class's canonical `toVerificationKey2020()` exporter (so it also carries
  the key's `id`), and its shape is exported as `VerificationKeyDescriptor`,
  defined in terms of `IVerificationKeyPair2020` from
  `@interop/data-integrity-core`.
- `KmsClient` constructor option `allowInsecureLoopback` (default `true`): set
  to `false` to disable the development exception that allows plain-`http`
  invocation targets on loopback hosts.

### Fixed

- **`Hmac.verify()` no longer caches results by data alone.** The memoize key
  previously omitted the signature, so within the cache TTL a forged signature
  for already-verified data was accepted from the cache (and a valid signature
  after a failed verification was wrongly rejected). The cache key now includes
  the signature and is encoded unambiguously (a JSON array), so distinct
  `(data, signature)` pairs cannot collide on one key.
- The https-or-loopback-http invocation-target check is now enforced for every
  KMS request in the shared `_invoke` path -- including targets derived from a
  `keyId`/`keystoreId` (previously only capability-derived targets were checked,
  so e.g. `sign({keyId: 'http://any.host/...'})` sent a signed invocation over
  plain http) and `createKeystore`'s `url`.
- Base64 decoding of KMS response fields (`wrappedKey`, `unwrappedKey`,
  `signatureValue`, `secret`) now tolerates padded base64url and standard
  (`+`/`/` alphabet) base64 in addition to unpadded base64url. The strict
  decoder adopted in the `@scure/base` migration threw on such responses.
  Requests still emit unpadded base64url.
- `getKeyDescription({keyId})` (no capability) now targets the key's URL; it
  previously left the request URL undefined, so
  `AsymmetricKey.getKeyDescription()` on a key constructed from an `id` alone
  always threw `Invalid URL`. This also disambiguates the key description cache
  key per key.
- `KeystoreAgent.generateKey` can now resolve a key class for both documented
  call shapes: `{category}` alone (e.g. `{category: 'kek'}`) uses the
  recommended key type for that category, and a custom `type` URL (e.g.
  `urn:webkms:multikey:P-256`) is supported when passed together with
  `category`. A custom `type` without `category`, an unknown category, or a call
  with neither now throw clear errors. A key category name passed via `type`
  (deprecated) is normalized into `category` first, so it can no longer silently
  override an explicit, conflicting `category` (such conflicts now throw instead
  of generating a key of the wrong type server-side).
- Malformed or empty KMS responses now throw clear, attributed errors
  (`Invalid WebKMS server response: ...`) instead of opaque decode/destructure
  errors: `wrapKey`/`unwrapKey`/`sign`/`deriveSecret` validate the expected
  field before decoding, `verify` requires a boolean `verified`, and
  `generateKey` requires `keyId` and `keyDescription`. In addition,
  `getKeyDescription`, `getKeystore`, `updateKeystore`, and `createKeystore` now
  require an object response body (checked centrally in `_invoke`), so an empty
  or HTML body can no longer be returned typed as a config -- or, for key
  descriptions, memoized in the process-wide cache.
- The four `fromCapability` factories now throw a clear
  `"capability" is required.` error when called without a capability, instead of
  the misleading `"keyId" must be a string.`
- `AsymmetricKey.getAlgorithm()` called without arguments (or without a
  `keyDescription`) returns `undefined` instead of throwing.
- `generateKey`'s `maxCapabilityChainLength` validation now rejects
  non-integers, as its error message always claimed.
- `Hmac`/`Kek` KMS operations now target `kmsId` (the key's ID with the KMS)
  instead of the public `id`, consistent with `AsymmetricKey` and
  `KeyAgreementKey`; `Kek` now accepts and stores a `kmsId` (default:
  `options.id`). No behavior change unless a public alias differs from the KMS
  id.
- If the server returns an unrecognized key `type` after
  `KeystoreAgent.generateKey` created a key, the error now states that the key
  exists server-side instead of surfacing a bare constructor error.

### Changed

- Relax the `https:`-only capability invocation-target check
  (`KmsClient._getInvocationTarget`) to also accept plain-`http:` targets on
  loopback hosts (`localhost` / `127.0.0.1` / `[::1]`). Delegated zcaps can now
  be invoked against a KMS on a local development server; all non-loopback
  targets still require `https:`.
- `Hmac` no longer schedules a self-rescheduling cache-prune timer; cache
  entries expire via the LRU cache's own TTL. Idle `Hmac` instances no longer
  hold the Node.js event loop open (for up to 3s) after a cached operation.
- Collapsed the near-identical `KmsClient` method bodies into shared
  `_invoke`/`_resolveTarget` helpers; the 409-to-`DuplicateError` mapping now
  lives in the shared error handler. `revokeCapability` and the static
  `createKeystore` now go through the same helpers, so `createKeystore` also
  maps a 409 to a `DuplicateError` (message `Duplicate keystore.`). Other
  request and error shapes are unchanged.
- The four key classes now share one `fromCapability` implementation
  (`src/keyHelpers.ts`). `Hmac.fromCapability`/`Kek.fromCapability` now prefer
  the key description's `id` (falling back to the capability's invocation
  target, the previous behavior) for the public `id`, matching the other key
  classes.
- `AsymmetricKey.getKeyDescription()` clones via `structuredClone` instead of
  `JSON.parse(JSON.stringify(...))`.
- Replaced pervasive `any` types with real interfaces and typed method returns,
  using the shared `@interop/data-integrity-core` types (new dependency):
  capabilities are `IZcap | string`, invocation signers are `ISigner`, and key
  descriptions are `KeyDescription` (an exported alias for
  `IPublicKey2020 | IPublicMultikey`). Only `KeystoreConfig` and
  `KeyDescription` (WebKMS-specific) are defined and exported here.
- The signer returned by `CapabilityAgent.getSigner()` no longer carries a
  `type` property (nothing consumed it); it is a plain `ISigner` (`id`,
  `algorithm`, `sign`).
- `KmsClient.createKeystore` dropped dead code: the capability-based `url`
  derivation branch (unreachable because `url` is asserted first) and the
  `this.agent` fallback (always undefined in a static method).
- Operations invoked without a `capability` now throw a clear `TypeError` when
  the fallback key/keystore ID is also missing, instead of building a
  `urn:zcap:root:undefined` capability and failing at the network layer.

## 14.4.2 - 2026-06-30

### Fixed

- `CapabilityAgent.fromSecret` no longer collapses distinct binary
  (`Uint8Array`) secrets to the same key. The salted-hash input previously
  decoded the secret through `TextDecoder` (UTF-8), mapping invalid byte
  sequences to U+FFFD, so different binary secrets could derive an identical
  seed and `did:key`. Binary secrets are now hashed as raw bytes. String-secret
  derivation is unchanged (verified byte-identical), so only keys derived from
  binary secrets are affected.

## 14.4.0-14.4.1 - 2026-06-29

### Changed

- **Forked to `@interop/webkms-client`.** Published under the `@interop` npm
  scope from `https://github.com/interop-alliance/webkms-client`. No changes to
  library behavior, public API, or return shapes.
- **Infrastructure migration to the `isomorphic-lib-template`.** No changes to
  library behavior, public API, or return shapes.
  - Converted the source from JavaScript to TypeScript (`lib/*.js` to
    `src/*.ts`); the package now builds to `dist/` via `tsc` with type
    declarations and sourcemaps.
  - Switched the package manager to pnpm.
  - Replaced the test stack: mocha + chai + karma are now vitest (Node) and
    Playwright (browser).
  - Replaced the ESLint setup with the flat config (eslint 10 +
    typescript-eslint) and added Prettier.
  - Raised the minimum supported Node.js engine to `>=24`.
  - Reworked CI (GitHub Actions) and added an npm publish workflow with
    provenance.
  - Updated package `exports` to resolve to `dist`.
- **Swapped dependencies for `@interop` and `@scure` counterparts.** No changes
  to library behavior, public API, or return shapes.

### Fixed

- `Hmac` cache pruning now checks `cache.size` instead of the removed
  `cache.length` property, so an emptied cache correctly stops rescheduling its
  prune timer.

### Removed

- Dropped the Codecov upload; coverage is now generated locally
  (`pnpm run test:coverage`).
- Removed the `src/crypto.ts` / `src/crypto-browser.ts` isomorphic split and the
  `browser` field that swapped them. Both resolved to a standard Web Crypto
  object; on Node.js 24+ and modern browsers, `globalThis.crypto` is used
  directly.

## 14.3.0 - 2025-01-17

### Added

- Allow a more specific key type to be specified in `generateKey()`. This change
  is backwards compatible, however, the `type` parameter should now carry the
  specific key type whereas it was previously used to specify the key category
  (e.g., `asymmetric`, `symmetric`). This key category should now be specified
  via the new parameter `category`. The existing category values are still
  usable in the `type` parameter, but this use is deprecated.

## 14.2.0 - 2025-05-22

### Changed

- Use `@digitalbazaar/lru-memoize@4`.

## 14.1.2 - 2024-09-19

### Fixed

- Allow `zUC6` multibase header for `Bls12381G2` keys.

## 14.1.1 - 2024-07-10

### Added

- Assert `KmsClient.createKeystore()` return value is well-formed.

## 14.1.0 - 2024-04-12

### Added

- Add support for BLS12-381 keys.

## 14.0.0 - 2024-01-24

### Changed

- **BREAKING**: Remove contexts from WebKMS payloads. WebKMS payloads are now
  treated as JSON instead of JSON-LD invocation of a method must be done using
  an authz mechanism that treats operations as such, e.g., zcap invocation using
  HTTP signatures.

## 13.0.1 - 2023-09-20

### Fixed

- Assign `cause.data` to `error.data` in `_handleClientError` helper.
  `error.data` was inadvertently removed in `v12.1.2`.

## 13.0.0 - 2023-09-13

### Changed

- **BREAKING**: Drop support for Node.js < 18.
- Use `@digitalbazaar/http-client@4` which requires Node.js 18+.

## 12.1.2 - 2023-09-12

### Fixed

- Do not overwrite an existing `error.cause` value.
- Utilize the `message` parameter passed to the `_handleClientError` helper.

## 12.1.1 - 2023-08-22

### Fixed

- Ensure that when using a root zcap with `fromCapability` static helper
  functions, the invocation target is calculated correctly.

## 12.1.0 - 2022-09-15

### Added

- `AsymmetricKey` now sets `algorithm` using the prefix of the
  `publicKeyMultibase`.

## 12.0.0 - 2022-08-02

### Removed

- Remove `CapabilityAgent` seed cache feature (including `fromCache` API). It is
  typically (if not always) unused and unnecessary; removing it reduces attack
  surface.

## 11.1.0 - 2022-08-02

### Added

- Enable passing `capability` as an option to `KeystoreAgent.generateKey`.

## 11.0.0 - 2022-06-09

### Changed

- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- **BREAKING**: Use `globalThis` for browser crypto and streams.
- **BREAKING**: Require Web Crypto API. Older browsers and Node.js 14 users need
  to install an appropriate polyfill.
- Update dependencies.
- Lint module.

## 10.0.0 - 2022-03-01

### Changed

- **BREAKING**: Better future proof zcap endpoints by posting zcap revocations
  to `/zcaps/revocations` instead of just `/revocations`.

## 9.3.0 - 2022-02-27

### Added

- Allow `kmsId` to be set in `Hmac` instances (and default to `id`) for
  consistency with other keys.

### Changed

- Change underlying cache implementation in `Hmac` to use
  `@digitalbazaar/lru-memoize` to improve maintainability and code reuse.

### Fixed

- Ensure `cache` is marked as a private member `_cache` of `Hmac`.

## 9.2.1 - 2022-02-16

### Fixed

- Fix missing `cause` param.

## 9.2.0 - 2022-02-02

### Fixed

- Fix `fromCapability` static helper functions so that a default `KmsClient`
  instance will be created to match the documentation.

## 9.1.0 - 2022-01-14

### Added

- Allow `maxCapabilityChainLength` to be specified when generating a key. This
  field can be used to express the maximum acceptable length of a capability
  chain associated with a capability invocation at an invocation target, i.e.,
  at a key URL.

## 9.0.0 - 2022-01-11

### Changed

- **BREAKING**: Key constructors cannot be called directly when using a
  `capability`. Instead, call `.fromCapability` on the appropriate key class.
  This change allows key instances to be created asynchronously, which is
  necessary to obtain public key description information prior to using an
  asymmetric key to sign.
- **BREAKING**: `generateKey` now returns `{keyId, keyDescription}`. This
  provides the KMS ID for the key along with whatever `id` is set in the key
  description, which is the `id` for the public key (which may be different)
  from the KMS key ID.

## 8.0.1 - 2021-12-09

### Fixed

- Fix `headers` and `method` passed into `signCapabilityInvocation()` in
  `createKeystore()` and `getKeystore()`.

## 8.0.0 - 2021-12-01

### Changed

- **BREAKING**: Update error messages, make them more specific. Add `cause`
  property to the thrown errors, and include `requestUrl` for timeout and
  network errors.

## 7.0.1 - 2021-08-27

### Fixed

- Fix internal `_assert` helper; it should have been synchronous but was marked
  async.

## 7.0.0 - 2021-07-22

### Changed

- **BREAKING**: All root zcaps use `urn:root:zcap:` prefix. Root zcaps for keys
  are the keystore root zcap where the controller resides, not the key. This new
  client version must be paired with a new WebKMS server, it is not compatible
  with an old version.
- **BREAKING**: `getKeystore` is now an instance member function instead of a
  static class member function. It requires that a capability be invoked to
  fetch the keystore config.
- **BREAKING**: The `keystore` parameter passed to `KmsClient` and
  `KeystoreAgent` constructors has been renamed to `keystoreId` to help avoid
  confusion (it is a string that contains the ID of a keystore, not the keystore
  config).
- **BREAKING**: Use simplified zcap revocation model via `revokeCapability`. Now
  any party that has delegated a zcap may revoke it by calling
  `revokeCapability` with the revoked zcap without passing an additional
  capability that targets a revocation endpoint. If no capability is passed,
  then the client will a root zcap at the `<keystoreId>/revocations/<zcap ID>`
  endpoint. The controller for this target is expected to be the delegator of
  the zcap.
- **BREAKING**: `KmsClient` functions that previously returned base64url-encoded
  results will now base64url-decode and return a `Uint8Array` instead. The APIs
  for `AsymmetricKey` and `KeyAgreementKey` will not be changed as they already
  returned a `Uint8Array` (instead, the decoding will just be moved to
  KmsClient). However, `Hmac.sign()` and `Kek.wrapKey()` will now return a
  `Uint8Array`. This change moves all encoding decisions that are related to the
  WebKMS HTTP API only inside of the `KmsClient` for consistency.
- **BREAKING**: Require `suiteContextUrl` be passed to `KmsClient` along with
  the key type. This allows decoupling of this library from `crypto-ld`,
  enabling them to evolve independently. This library still supports a single
  recommended key algorithm per type of key when using `KeystoreAgent`, e.g.,
  `keyAgreement`, `kek`, `hmac`, `asymmetric`.
- **BREAKING**: Creating a keystore now requires an `invocationSigner` as the
  request signs a zcap for the keystore creation endpoint as its invocation
  target.

### Removed

- **BREAKING**: Remove `enableCapability` and `disableCapability`. To revoke a
  delegated authorized zcap, revoke it via `revokeCapability` instead.
- **BREAKING**: Remove built-in support for older keys (e.g.,
  `Ed25519Signature2018`). These can still be generated if the WebKMS server
  supports them, but their `suiteContextUrl` must be passed to
  `KmsClient.generateKey()`, they are not supported via `KeystoreAgent`.
- **BREAKING**: Remove `keyType` option from `CapabilityAgent`.
- **BREAKING**: Remove `findKeystores` API. It was unused, would require changes
  to work with the other changes in this new version, and its unclear how much
  of a benefit it is at this time. A redesign of this API may come back in a
  future version if it makes sense to do so.

## 6.0.0 - 2021-05-04

### Changed

- Update dependencies.
  - **BREAKING**: Remove `security-context` and Use
    [webkms-context@1.0](https://github.com/digitalbazaar/webkms-context/blob/main/CHANGELOG.md).
  - Use
    [`aes-key-wrapping-2019-context@1.0.3`](https://github.com/digitalbazaar/aes-key-wrapping-2019-context/blob/main/CHANGELOG.md).
  - Use
    [`sha256-hmac-key-2019-context@1.0.3`](https://github.com/digitalbazaar/sha256-hmac-key-2019-context/blob/main/CHANGELOG.md).

## 5.0.1 - 2021-04-13

### Fixed

- Include `cryptoLd.js` file to files section in package.json.

## 5.0.0 - 2021-04-08

### Changed

- **BREAKING**: Rename NPM package from `webkms-client` to
  `@digitalbazaar/webkms-client`.
- Add support for multiple asymmetric key types (`Ed25519VerificationKey2018`,
  `Ed25519VerificationKey2020`, `X25519KeyAgreementKey2019`,
  `X25519KeyAgreementKey2020`) via `crypto-ld`.

## 4.0.0 - 2021-03-17

### Changed

- **BREAKING**: Switch from using `Ed25519VerificationKey2018` key types to
  `Ed25519VerificationKey2020` for capability signing. See
  [`crypto-ld v4`](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)
  changelog. See also instructions on
  [converting and upgrading from Ed25519VerificationKey2018](https://github.com/digitalbazaar/ed25519-verification-key-2020#converting-from-previous-ed25519verificationkey2018-key-type)
- Remove `crypto-ld` as a dependency (it's still used by individual key suites).
- **BREAKING**: Drop support for Node 10 (it's moving out of LTS).

## 3.1.0 - 2021-03-08

### Added

- Add optional `defaultHeaders` parameter to the KmsClient constructor. This
  allows additional headers to be included with KMS requests.

## 3.0.0 - 2021-03-02

### Changed

- Use `http-signature-zcap-invoke@3`. Numerous breaking changes here related to
  dates in the http-signature header.

## 2.5.0 - 2021-03-02

### Added

- Implement KmsClient.updateKeystore API.
- Implement KeystoreAgent.updateConfig API.

## 2.4.0 - 2021-03-01

### Changed

- HMAC cache expiration is extended on `get`.

## 2.3.2 - 2020-09-30

### Fixed

- Move `crypto-ld` from devDependencies to dependencies.

## 2.3.1 - 2020-08-14

### Fixed

- Fix searchParams option httpClient.get API call.

## 2.3.0 - 2020-06-24

### Added

- Add an LRU cache to improve performance for HMAC operations.

## 2.2.0 - 2020-06-19

### Changed

- Use `@digitialbazaar/http-client` in place of `axios` for HTTP requests.

## 2.1.0 - 2020-04-21

### Added

- Setup CI and coverage workflow.

### Changed

- Update deps.

## 2.0.1 - 2020-02-10

### Changed

- Use zcap-invoke@1.1.1.

## 2.0.0 - 2020-02-07

### Added

- Add `revokeCapability` API.
- Add `CapabilityAgent`.
- Add `KeystoreAgent`.

### Removed

- **BREAKING**: Removed `ControllerKey` and replaced with `CapabilityAgent` and
  `KeystoreAgent`.

## 1.1.0 - 2020-01-11

### Added

- Allow `authorizations` zcaps.

## 1.0.0 - 2019-12-18

### Added

- Add core files.

- See git history for changes previous to this release.
