# Plan: replace the copied `vc` directories with endorser-vc

The JWT/DID verification code lives in four copies that have diverged:

| Repo | Path |
|---|---|
| endorser-ch | `src/api/services/vc/` |
| image-api | `src/vc/` |
| notification-wakeup-service | `src/vc/` |
| crowd-funder-for-time-pwa | `src/libs/crypto/vc/` |

This package merges them. [CHANGELOG.md](../CHANGELOG.md) lists every behavior difference
a consumer sees when it switches.

## Checklist

- [x] 1. Create the repo: TypeScript, ESM + CJS build with tsup, one entry point
- [x] 2. Reconcile the copies into one source
- [x] 3. Remove host-app coupling: options instead of `process.env`, an injected logger,
      structural types instead of Veramo/app types, WebCrypto and `Uint8Array` instead of Node
      `crypto` and `Buffer`
- [x] 4. Tests: generated vectors for each path, real-authenticator vectors from endorser-ch,
      ESM/CJS smoke tests on `dist`
- [ ] 5. Try it in the real consumers before publishing (`npm pack`, install the tarball)
- [ ] 6. Publish
- [ ] 7. Migrate the consumers, least risky first: image-api, notification-wakeup-service,
      endorser-ch, crowd-funder-for-time-pwa
- [ ] 8. In each consumer's AGENTS.md, point verification changes at this package

## Outstanding

- [ ] Hub bare repo and backed-check entry — next: create `restart-mac:git/endorser-vc.git`, add the remote, push, add a line to `~/.config/backed/backed-check.conf` (Trent)
- [ ] GitHub repo — next: create `trentlarson/endorser-vc` (named in package.json) and push (Trent)
- [ ] Publish 0.0.1 to npmjs.com — next: `pkgx npm login`, then `pkgx npm publish` after the GitHub push; `publishConfig` pins the registry and public access (Trent)
- [ ] endorser-ch invite fixes (bad passkey signature, signer ≠ requester, agent ≠ signer, registered user redeeming; CHANGELOG Unreleased; suite 8) — next: review and commit (Trent)
- [ ] notification-wakeup-service rejects every passkey token — next: fix by migrating (Trent)

## Migration notes per consumer

**All:** delete the local `vc` directory in the same commit that adds the dependency. Remove
dependencies only it used (`base64url`, and possibly `cbor-x`, `@peculiar/asn1-*`).

**image-api:** replace `NODE_ENV === "test-local"` with
`createVerifier({ testOnlySkipPeerExpiry: true, testOnlySkipEthrVerification: true })` in test
setup. Confirm the Docker build resolves did-jwt.

**notification-wakeup-service:** same test options as image-api. `authJwtLifetimeProblem`
sees the moved `exp` under `testOnlySkipEthrVerification`. `decodeAndVerifyDelegatedJwt` keeps
its error codes. Passkey tokens start verifying.

**endorser-ch:** build one verifier at startup from `SERVICE_AUDIENCE_ID`,
`SERVICE_AUDIENCE_REQUIRED`, and `UNAUDIENCED_LOG_INTERVAL_MS`, with the logger `l` (its `warn`
expects `LOG_LEVEL=warn` or lower), plus `testOnlySkipPeerExpiry` when `NODE_ENV` is
`test-local`. It is consumed through Babel as CJS. Its peer tests (`1 - Peer DID`) check status
codes, which don't change.

**crowd-funder-for-time-pwa:** `createEndorserJwtForKey`, `decodeEndorserJwt`,
`ETHR_DID_PREFIX`, `isFromPasskey`, `createPeerDid`, and `unwrapEC2Signature` keep their names.
Unlike the other consumers, `src/libs/crypto/vc/` shrinks to one app file instead of
disappearing, because these stay in the app and import their helpers (`cborToKeys`,
`peerDidToPublicKeyBytes`, `verifyPeerSignature`, `unwrapEC2Signature`) from endorser-vc:
- `registerCredential`, which `src/libs/util.ts` calls to create a passkey; it needs
  `@simplewebauthn` and `AppString`.
- `PeerSetup`, `verifyJwtP256`, `verifyJwtSimplewebauthn`, and `verifyJwtWebCrypto`, used only by
  the passkey experiments in `src/views/TestView.vue`. They can move beside TestView, or go along
  with the experiments; `verifyJwtP256`'s own comment says it doesn't verify.
- `urlBase64ToUint8Array`, which `src/components/PushNotificationPermission.vue` uses.

`verifyJwtWebCrypto` is the only caller of the app's `verifyPeerSignature(data, did, rawSig)`.
With endorser-vc it becomes `verifyPeerSignature(data, peerDidToPublicKeyBytes(did), derSig)` and
drops its own `unwrapEC2Signature` call, since endorser-vc unwraps the DER signature itself.

The app's `decodeAndVerifyJwt` has no callers; it goes with the rest of the directory. The comment
in `src/libs/crypto/backgroundJwtPool.ts` that names `createJwtNavigator` should name
endorser-vc's `createDidPeerJwt`. The `buffer/` polyfill can go if nothing else uses it.

## History

- Package name `@endorser/endorser-vc`, public on npm under the `endorser` organization; nothing in
  the code is private. *(2026-10-29)*
  - Rejected: unscoped `endorser-vc`, chosen first to avoid creating an npm organization.
- One entry point rather than verify/sign/browser subpaths: none of them pulls in a dependency
  the others don't, and the browser-only function touches browser globals only when called.
  *(2026-10-29)*
- A failed passkey signature rejects instead of resolving `verified: false`; every caller treats
  the two the same, except one that forgot to check. *(2026-10-29)*
