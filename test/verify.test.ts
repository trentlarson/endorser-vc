import { describe, expect, it } from "vitest";

import {
  base64urlEncodeString,
  createVerifier,
  DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE,
  decodeAndVerifyDelegatedJwt,
  decodeAndVerifyJwt,
  identitySupportsDelegatedJwtBatch,
  INVALID_AUDIENCE_CODE,
  JWT_VERIFY_FAILED_CODE,
  UNSUPPORTED_DID_METHOD_CODE,
} from "../src/index";
import { epochNow, ethrJwt, newEthrIdentity, newPasskey, passkeyJwt } from "./fixtures";

const claim = { "@context": "https://schema.org", "@type": "GiveAction", object: "a test" };

/** Expect a rejection with { clientError: { code } } and return its message. */
async function rejectionCode(promise: Promise<unknown>): Promise<string> {
  const e = await promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (e: unknown) => e,
  );
  expect(e).toHaveProperty("clientError.message");
  return (e as { clientError: { code: string } }).clientError.code;
}

function unsignedJwt(header: object, payload: object, signature = "c2ln"): string {
  return (
    base64urlEncodeString(JSON.stringify(header)) +
    "." +
    base64urlEncodeString(JSON.stringify(payload)) +
    "." +
    signature
  );
}

describe("did:ethr", () => {
  const alice = newEthrIdentity();
  const bob = newEthrIdentity();

  it("verifies a good token", async () => {
    const result = await decodeAndVerifyJwt(await ethrJwt(alice, { vc: claim }, 60));
    expect(result.verified).toBe(true);
    expect(result.issuer).toBe(alice.did);
    expect(result.payload.iss).toBe(alice.did);
    expect(result.payload.vc).toEqual(claim);
  });

  it("rejects an expired token", async () => {
    const jwt = await ethrJwt(alice, { vc: claim, exp: epochNow() - 1000 });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects a token signed by someone other than its issuer", async () => {
    const jwt = await ethrJwt(bob, { vc: claim, iss: alice.did }, 60);
    // createJWT sets iss from its issuer option, so forge the payload instead
    const [h, , s] = jwt.split(".");
    const forged = h + "." + base64urlEncodeString(JSON.stringify({ iss: alice.did, vc: claim })) + "." + s;
    expect(await rejectionCode(decodeAndVerifyJwt(forged))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects a tampered payload", async () => {
    const jwt = await ethrJwt(alice, { vc: claim }, 60);
    const [h, p, s] = jwt.split(".");
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    payload.vc = { ...claim, object: "something else" };
    const tampered = h + "." + base64urlEncodeString(JSON.stringify(payload)) + "." + s;
    expect(await rejectionCode(decodeAndVerifyJwt(tampered))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects a future nbf in normal verification but accepts it as delegated", async () => {
    const jwt = await ethrJwt(alice, { vc: claim, nbf: epochNow() + 86400, exp: epochNow() + 2 * 86400 });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
    const result = await decodeAndVerifyDelegatedJwt(jwt);
    expect(result.verified).toBe(true);
    expect(result.issuer).toBe(alice.did);
  });

  it("skips the signature only when testOnlySkipEthrVerification is set, moving an expired exp", async () => {
    const forged = unsignedJwt({ typ: "JWT", alg: "ES256K" }, { iss: alice.did, exp: epochNow() - 1000 });
    expect(await rejectionCode(decodeAndVerifyJwt(forged))).toBe(JWT_VERIFY_FAILED_CODE);
    const testVerifier = createVerifier({ testOnlySkipEthrVerification: true });
    const result = await testVerifier.decodeAndVerifyJwt(forged);
    expect(result.verified).toBe(true);
    expect(result.payload.exp).toBeGreaterThan(epochNow());
  });
});

describe("audience", () => {
  const alice = newEthrIdentity();
  const service = "https://endorser.example";

  it("ignores aud when no audience is configured, unlike did-jwt's default", async () => {
    const jwt = await ethrJwt(alice, { vc: claim, aud: "https://elsewhere.example" }, 60);
    expect((await decodeAndVerifyJwt(jwt, { checkAudience: true })).verified).toBe(true);
  });

  it("accepts a matching aud, including inside an array", async () => {
    const verifier = createVerifier({ audience: service });
    for (const aud of [service, ["https://other.example", service]]) {
      const jwt = await ethrJwt(alice, { vc: claim, aud }, 60);
      expect((await verifier.decodeAndVerifyJwt(jwt, { checkAudience: true })).verified).toBe(true);
    }
  });

  it("rejects a mismatched aud only when checkAudience is requested", async () => {
    const verifier = createVerifier({ audience: service });
    const jwt = await ethrJwt(alice, { vc: claim, aud: "https://elsewhere.example" }, 60);
    expect(await rejectionCode(verifier.decodeAndVerifyJwt(jwt, { checkAudience: true }))).toBe(
      INVALID_AUDIENCE_CODE,
    );
    expect((await verifier.decodeAndVerifyJwt(jwt)).verified).toBe(true);
  });

  it("accepts and reports a missing aud unless requireAudience is set", async () => {
    const warnings: string[] = [];
    const lenient = createVerifier({
      audience: service,
      logger: { warn: (m) => warnings.push(m) },
      unaudiencedLogIntervalMs: 0,
    });
    const jwt = await ethrJwt(alice, { vc: claim }, 60);
    expect((await lenient.decodeAndVerifyJwt(jwt, { checkAudience: true })).verified).toBe(true);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(alice.did);

    const strict = createVerifier({ audience: service, requireAudience: true });
    expect(await rejectionCode(strict.decodeAndVerifyJwt(jwt, { checkAudience: true }))).toBe(
      INVALID_AUDIENCE_CODE,
    );
  });

  it("applies to did:peer tokens too", async () => {
    const passkey = await newPasskey();
    const verifier = createVerifier({ audience: service });
    const wrong = await passkeyJwt(passkey, { vc: claim, aud: "https://elsewhere.example" });
    expect(await rejectionCode(verifier.decodeAndVerifyJwt(wrong, { checkAudience: true }))).toBe(
      INVALID_AUDIENCE_CODE,
    );
    const right = await passkeyJwt(passkey, { vc: claim, aud: service });
    expect((await verifier.decodeAndVerifyJwt(right, { checkAudience: true })).verified).toBe(true);
  });
});

describe("did:peer JWANT", () => {
  it("verifies a good token and returns the claim from the challenge", async () => {
    const passkey = await newPasskey();
    const result = await decodeAndVerifyJwt(await passkeyJwt(passkey, { vc: claim }));
    expect(result.verified).toBe(true);
    expect(result.issuer).toBe(passkey.did);
    expect(result.payload.vc).toEqual(claim);
    expect(result.payload.iss).toBe(passkey.did);
  });

  it("verifies a signature whose r or s is shorter than 32 bytes in DER", async () => {
    const passkey = await newPasskey();
    const jwt = await passkeyJwt(passkey, { vc: claim }, { requireShortComponent: true });
    expect((await decodeAndVerifyJwt(jwt)).verified).toBe(true);
  });

  it("rejects, rather than resolving unverified, when the signature doesn't match", async () => {
    const passkey = await newPasskey();
    const jwt = await passkeyJwt(passkey, { vc: claim }, { tamper: true });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects a token claiming another passkey's DID", async () => {
    const [mine, theirs] = [await newPasskey(), await newPasskey()];
    const jwt = await passkeyJwt(mine, { vc: claim }, { claimedDid: theirs.did });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects an expired token unless testOnlySkipPeerExpiry is set", async () => {
    const passkey = await newPasskey();
    const jwt = await passkeyJwt(passkey, { vc: claim }, { exp: epochNow() - 1000 });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
    const testVerifier = createVerifier({ testOnlySkipPeerExpiry: true });
    expect((await testVerifier.decodeAndVerifyJwt(jwt)).verified).toBe(true);
  });

  it("rejects a did:peer token that isn't a JWANT", async () => {
    const passkey = await newPasskey();
    const jwt = unsignedJwt({ typ: "JWT", alg: "ES256" }, { iss: passkey.did, exp: epochNow() + 60 });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("is refused as a delegated token", async () => {
    const passkey = await newPasskey();
    const jwt = await passkeyJwt(passkey, { vc: claim });
    expect(await rejectionCode(decodeAndVerifyDelegatedJwt(jwt))).toBe(
      DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE,
    );
    expect(identitySupportsDelegatedJwtBatch(passkey.did)).toBe(false);
    expect(identitySupportsDelegatedJwtBatch(newEthrIdentity().did)).toBe(true);
  });
});

describe("malformed input", () => {
  it.each([
    ["not a JWT", "nope"],
    ["two pieces", "a.b"],
    ["bad base64 JSON", "e30.!!!.c2ln"],
    ["JSON that isn't an object", base64urlEncodeString("{}") + "." + base64urlEncodeString("3") + ".c2ln"],
  ])("rejects %s with a clientError", async (_label, jwt) => {
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
    expect(await rejectionCode(decodeAndVerifyDelegatedJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects a missing iss", async () => {
    const jwt = unsignedJwt({ typ: "JWT" }, { exp: epochNow() + 60 });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(JWT_VERIFY_FAILED_CODE);
  });

  it("rejects other DID methods", async () => {
    const jwt = unsignedJwt({ typ: "JWT" }, { iss: "did:web:example.com" });
    expect(await rejectionCode(decodeAndVerifyJwt(jwt))).toBe(UNSUPPORTED_DID_METHOD_CODE);
    expect(await rejectionCode(decodeAndVerifyDelegatedJwt(jwt))).toBe(UNSUPPORTED_DID_METHOD_CODE);
  });

  it("rejects a JWANT with an unparseable signature or key", async () => {
    const passkey = await newPasskey();
    const jwt = await passkeyJwt(passkey, { vc: claim });
    const [h, p] = jwt.split(".");
    expect(await rejectionCode(decodeAndVerifyJwt(h + "." + p + ".AAAA"))).toBe(JWT_VERIFY_FAILED_CODE);
    const badDid = await passkeyJwt(passkey, { vc: claim }, { claimedDid: "did:peer:0zNotAKey" });
    expect(await rejectionCode(decodeAndVerifyJwt(badDid))).toBe(JWT_VERIFY_FAILED_CODE);
  });
});
