// Load the built ESM entry the way a consumer would, and verify a real token.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createVerifier, JWT_VERIFY_FAILED_CODE } from "@endorser/endorser-vc";

const { jwts } = JSON.parse(readFileSync(new URL("./vectors-real-passkey.json", import.meta.url)));
const result = await createVerifier({ testOnlySkipPeerExpiry: true }).decodeAndVerifyJwt(jwts.Good);
assert.equal(result.verified, true);
assert.equal(JWT_VERIFY_FAILED_CODE, "JWT_VERIFY_FAILED");
console.log("ESM dist OK");
