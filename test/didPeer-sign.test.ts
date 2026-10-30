import { describe, expect, it } from "vitest";

import {
  cborToKeys,
  createEndorserJwtForKey,
  createPeerDid,
  decodeAndVerifyJwt,
  decodeEndorserJwt,
  isFromPasskey,
  peerDidToPublicKeyBytes,
  unwrapEC2Signature,
} from "../src/index";
import { derEncodeSignature, newEthrIdentity, newPasskey } from "./fixtures";

describe("did:peer keys", () => {
  it("round-trips a COSE key through a DID", async () => {
    const passkey = await newPasskey();
    expect(passkey.did.startsWith("did:peer:0z")).toBe(true);
    expect(peerDidToPublicKeyBytes(passkey.did)).toEqual(passkey.publicKeyCose);
    expect(createPeerDid(peerDidToPublicKeyBytes(passkey.did))).toBe(passkey.did);
    const { publicKeyJwk, publicKeyBuffer } = cborToKeys(passkey.publicKeyCose);
    expect(publicKeyJwk).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256" });
    expect(publicKeyBuffer).toHaveLength(64);
  });

  it("refuses a key that isn't P-256 COSE", () => {
    expect(() => cborToKeys(new Uint8Array([0xa0]))).toThrow("Unable to extract key.");
  });

  it("unwraps DER signatures to exactly 64 bytes, padding short components", () => {
    const raw = new Uint8Array(64);
    raw.fill(0x7f, 0, 32); // r without a high bit: DER keeps 32 bytes
    raw.fill(0xff, 32, 64); // s with a high bit: DER adds a 0x00
    raw[0] = 0; // r with a leading zero byte: DER drops it
    raw[1] = 0;
    const der = derEncodeSignature(raw);
    expect(unwrapEC2Signature(der)).toEqual(raw);
  });
});

describe("signing", () => {
  it("signs with a Veramo identity and verifies", async () => {
    const alice = newEthrIdentity();
    const identity = JSON.stringify({ did: alice.did, keys: [{ privateKeyHex: alice.privateKeyHex }] });
    const jwt = await createEndorserJwtForKey({ did: alice.did, identity }, { vc: { a: 1 } }, 60);
    expect(decodeEndorserJwt(jwt).header.alg).toBe("ES256K");
    // 64-byte signature, without the recovery byte
    expect(Buffer.from(jwt.split(".")[2], "base64url")).toHaveLength(64);
    const result = await decodeAndVerifyJwt(jwt);
    expect(result.issuer).toBe(alice.did);
    expect(result.payload.exp).toBeTypeOf("number");
  });

  it("refuses an account without key data", async () => {
    await expect(createEndorserJwtForKey({ did: "did:ethr:0x0" }, {})).rejects.toThrow(
      "No identity data found",
    );
  });

  it("tells passkey accounts apart", () => {
    expect(isFromPasskey({ passkeyCredIdHex: "ab" })).toBe(true);
    expect(isFromPasskey({})).toBe(false);
    expect(isFromPasskey(undefined)).toBe(false);
  });
});
