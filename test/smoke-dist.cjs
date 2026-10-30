// Load the built CJS entry the way a consumer would, and verify a real token.
const assert = require("node:assert/strict");
const { createVerifier, JWT_VERIFY_FAILED_CODE } = require("@endorser/endorser-vc");
const { jwts } = require("./vectors-real-passkey.json");

createVerifier({ testOnlySkipPeerExpiry: true })
  .decodeAndVerifyJwt(jwts.Good)
  .then((result) => {
    assert.equal(result.verified, true);
    assert.equal(JWT_VERIFY_FAILED_CODE, "JWT_VERIFY_FAILED");
    console.log("CJS dist OK");
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
