# endorser-vc

Create and verify the JWTs that [Endorser Search](https://github.com/trentlarson/endorser-ch) and
Time Safari exchange. Two kinds of issuer are supported:

- **did:ethr** — an ES256K JWT signed with a secp256k1 key. The DID is resolved locally from its
  Ethereum address, with no network lookup.
- **did:peer:0** (passkeys) - EXPERIMENTAL — a *JWANT*: a JWT-shaped token carrying a WebAuthn assertion. Its
  header is `{ "typ": "JWANT", "alg": "ES256" }`, its payload holds the WebAuthn
  `AuthenticationDataB64URL` and `ClientDataJSONB64URL`, and its signature is the WebAuthn
  signature over `authenticatorData || sha256(clientDataJSON)`. The claim travels as the WebAuthn
  challenge inside the client data. (There is code to create and somewhat test these but they have not
  been tested with external passkey tools, nor verified anywhere besides development environments.)

One build serves Node (20+) and browsers, as ESM or CommonJS. It needs no Buffer polyfill;
cryptography goes through WebCrypto (`globalThis.crypto.subtle`).

```sh
npm install endorser-vc
```

## Verifying

```ts
import { createVerifier, decodeAndVerifyJwt } from "endorser-vc";

// defaults: no audience, no test bypasses
const { issuer, payload } = await decodeAndVerifyJwt(jwt);

// a server that binds credentials to itself
const verifier = createVerifier({
  audience: "https://api.endorser.ch",
  requireAudience: false,      // accept a missing "aud" while clients adopt it...
  logger: { warn: console.warn }, // ...and report hourly who omits it
});
await verifier.decodeAndVerifyJwt(authorizationJwt, { checkAudience: true }); // credentials
await verifier.decodeAndVerifyJwt(claimJwt);                                   // portable claims
```

Every failure rejects with the same shape, and every success has `verified: true`:

```ts
{ clientError: { message: string, code: string } }
```

| `code` | Meaning |
|---|---|
| `JWT_VERIFY_FAILED` | Malformed, expired, not yet valid, missing fields, or a bad signature |
| `INVALID_AUDIENCE` | `aud` is missing (with `requireAudience`) or names a different service |
| `UNSUPPORTED_DID_METHOD` | The issuer is neither did:ethr nor did:peer |
| `DELEGATED_JWT_UNSUPPORTED_IDENTITY` | A passkey token was given to `decodeAndVerifyDelegatedJwt` |

The codes are also exported as constants (`JWT_VERIFY_FAILED_CODE`, ...). Clients match on these
strings, so a change to one is a major version.

### Audience rules

Audience checking applies only when the call passes `{ checkAudience: true }`, which belongs on
the credential path; claims are portable and carry no audience.

- No `audience` configured: `aud` is ignored, whatever it says. (did-jwt on its own rejects any
  token carrying `aud` in that case.)
- `audience` configured: an `aud` that doesn't include it is rejected. A missing `aud` is
  accepted and counted for the logger's report, unless `requireAudience` is set.

The same rules apply to did:ethr and did:peer tokens.

### Delegated tokens

`decodeAndVerifyDelegatedJwt` accepts a did:ethr token whose `nbf` lies in the future, for batches
pre-issued to cover later days. Passkey tokens are refused there, since each one needs a live
assertion. `identitySupportsDelegatedJwtBatch(did)` tells a client in advance.

### Test options

These exist for test suites and must never be set in production. The library never reads
environment variables, so a deployment can't enable them by accident.

- `testOnlySkipPeerExpiry` — accept expired passkey tokens, since recorded fixtures can't be
  re-signed without a real authenticator.
- `testOnlySkipEthrVerification` — accept any did:ethr token without checking its signature, and
  move an expired `exp` to 100 seconds from now.

### Not checked

A JWANT's client-data `type` and `origin` and the authenticator's `rpIdHash` are not checked:
one did:peer identity is accepted by every deployment, whatever site created the passkey.

## Signing

```ts
import { createEndorserJwtForKey, createEthrJwt } from "endorser-vc";

// an account as Time Safari stores it: a Veramo identity, or a passkey credential ID
const jwt = await createEndorserJwtForKey(account, { vc: claim }, 60 /* expiresIn seconds */);

// or directly with a key
const jwt2 = await createEthrJwt(did, privateKeyHex, { vc: claim });
```

For a passkey account, `createEndorserJwtForKey` calls `createDidPeerJwt`, which prompts the
browser's authenticator through `navigator.credentials.get`. It only works in a browser.

## Other exports

- `createPeerDid(coseKey)` / `peerDidToPublicKeyBytes(did)` — between a WebAuthn
  `credentialPublicKey` and its did:peer:0 DID
- `cborToKeys(coseKey)` — a P-256 COSE key as a JWK
- `verifyPeerSignature(data, coseKey, derSignature)` — a bare WebAuthn signature check
- `verifyPasskeyJwt(payload, did, signature)` — the JWANT checks without the JWT parsing
- `didEthLocalResolver` — the did:ethr resolver, for use with did-jwt directly
- `decodeEndorserJwt(jwt)` — decode without verifying
- base64url helpers: `base64urlDecodeString`, `base64urlEncodeString`, `base64urlToBytes`,
  `bytesToBase64Url`, `toBase64Url`

## Development

```sh
npm install
npm test            # vitest
npm run typecheck   # src without Node types, then tests
npm run test:dist   # build, then load dist as ESM and CJS
```

`test/vectors-real-passkey.json` holds tokens from a real authenticator; `test/fixtures.ts` mints
fresh ones, including passkey tokens signed by a WebCrypto key standing in for an authenticator.

## License

Public domain, with the SQLite blessing; see [LICENSE](LICENSE).
