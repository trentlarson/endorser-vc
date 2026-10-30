# Changelog

## 0.0.1

First release, merging the `vc` directories copied into endorser-ch, image-api,
notification-wakeup-service, and crowd-funder-for-time-pwa. Behavior differs from those
copies as follows; each consumer should check these when it switches over.

- **`JWT_VERIFY_FAILED_CODE` is `"JWT_VERIFY_FAILED"`.** image-api and notification-wakeup-service
  used `"JWT_VERIFY_FAILED_CODE"`.
- **Every rejection carries a `code`**, including the passkey checks, a missing `iss`, and
  malformed tokens (which notification-wakeup-service threw as plain errors).
- **`aud` is ignored unless an audience is configured** (endorser-ch's rule). image-api and
  notification-wakeup-service used did-jwt's default, rejecting any token carrying `aud`.
- **Configuration is passed to `createVerifier`**, never read from the environment. The
  `NODE_ENV=test-local` bypasses map to `testOnlySkipPeerExpiry` (all copies) and
  `testOnlySkipEthrVerification` (image-api and notification-wakeup-service). The
  `SERVICE_AUDIENCE_*` variables map to `audience` and `requireAudience`.
- **`exp` must be a number** on passkey tokens; notification-wakeup-service skipped the expiry
  check for any other type.
- **A passkey token with a bad signature rejects** with `JWT_VERIFY_FAILED`. The copies resolved
  with `verified: false`, so a caller that didn't check `verified` accepted it.
- **Passkey signatures with a short `r` or `s` verify.** DER drops leading zero bytes, and the
  copies passed the shortened signature to WebCrypto, rejecting about 1 in 128 valid signatures.
- **Passkey tokens verify in notification-wakeup-service's variant.** Its key extraction required
  `Array.isArray` on CBOR byte strings, which are `Uint8Array`s, so every passkey token threw.
