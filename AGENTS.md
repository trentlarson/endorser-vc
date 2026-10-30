# endorser-vc

The JWT/DID verification and signing library for Endorser Search tools. Usage is in
[README.md](README.md); the plan and outstanding work are in
[CHANGES/PLAN-extract-vc.md](CHANGES/PLAN-extract-vc.md).

## Commands

```sh
npm test            # vitest
npm run typecheck   # src without Node types, then tests
npm run test:dist   # build, then load dist as ESM and CJS
```

`prepublishOnly` runs all three.

## Conventions

- `src` runs in Node and browsers: no `Buffer`, `process`, or Node `crypto`. The typecheck of
  `src` omits Node types to catch these.
- Every verification failure rejects with `{ clientError: { message, code } }`; a success has
  `verified: true`. Error code strings are part of the API.
- Configuration comes through `createVerifier` options, never the environment.
- Record behavior changes in [CHANGELOG.md](CHANGELOG.md); consumers read it when upgrading.
