import { describe, expect, it } from "vitest";

import { createVerifier, decodeAndVerifyJwt, JWT_VERIFY_FAILED_CODE } from "../src/index";
import vectors from "./vectors-real-passkey.json";

const { jwts } = vectors as { jwts: Record<string, string> };
const testVerifier = createVerifier({ testOnlySkipPeerExpiry: true });

describe("JWANTs from a real authenticator", () => {
  it("verifies the good one", async () => {
    const result = await testVerifier.decodeAndVerifyJwt(jwts.Good);
    expect(result.verified).toBe(true);
    expect(result.issuer.startsWith("did:peer:0z")).toBe(true);
    expect(result.payload.iss).toBe(result.issuer);
    expect(result.payload.vc).toBeTypeOf("object");
  });

  it("rejects the good one as expired without the test option", async () => {
    await expect(decodeAndVerifyJwt(jwts.Good)).rejects.toMatchObject({
      clientError: { code: JWT_VERIFY_FAILED_CODE, message: expect.stringContaining("expired") },
    });
  });

  it("rejects a forged token for a real passkey's DID, with a well-formed signature that signs nothing", async () => {
    const realDid = JSON.parse(Buffer.from(jwts.Good.split(".")[1], "base64url").toString()).iss;
    const exp = Math.floor(Date.now() / 1000) + 60;
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const challenge = b64({ claim: { "@type": "RegisterAction", identifier: "forged" }, exp, iss: realDid });
    const payload = {
      AuthenticationDataB64URL: Buffer.alloc(37, 1).toString("base64url"),
      ClientDataJSONB64URL: b64({ type: "webauthn.get", challenge, origin: "https://forged.example" }),
      exp,
      iss: realDid,
    };
    const der = Buffer.concat([
      Buffer.from([0x30, 0x44, 0x02, 0x20]),
      Buffer.alloc(32, 0x11),
      Buffer.from([0x02, 0x20]),
      Buffer.alloc(32, 0x22),
    ]);
    const forged = `${b64({ typ: "JWANT", alg: "ES256" })}.${b64(payload)}.${der.toString("base64url")}`;
    // the default verifier: rejects rather than resolving with verified: false
    await expect(decodeAndVerifyJwt(forged)).rejects.toMatchObject({
      clientError: { code: JWT_VERIFY_FAILED_CODE, message: expect.stringContaining("signature") },
    });
  });

  it.each(["BadSig", "MissingExp", "MismatchedExp", "MismatchedIss"])("rejects %s", async (name) => {
    await expect(testVerifier.decodeAndVerifyJwt(jwts[name])).rejects.toMatchObject({
      clientError: { code: JWT_VERIFY_FAILED_CODE },
    });
  });
});
