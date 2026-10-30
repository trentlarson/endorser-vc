/**
 * Mint real test tokens: did:ethr JWTs from a secp256k1 key, and JWANTs from a
 * P-256 key that stands in for a WebAuthn authenticator, signing exactly what a
 * browser authenticator signs.
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, toEthereumAddress } from "did-jwt";

import {
  base64urlEncodeString,
  bytesToBase64Url,
  createEthrJwt,
  createPeerDid,
  isoUint8ArrayConcat,
} from "../src/index";

export function epochNow(): number {
  return Math.floor(Date.now() / 1000);
}

export interface EthrIdentity {
  did: string;
  privateKeyHex: string;
}

export function newEthrIdentity(): EthrIdentity {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKeyHex = bytesToHex(secp256k1.getPublicKey(privateKey, false));
  return {
    did: "did:ethr:" + toEthereumAddress(publicKeyHex),
    privateKeyHex: bytesToHex(privateKey),
  };
}

export function ethrJwt(
  identity: EthrIdentity,
  payload: Record<string, unknown>,
  expiresIn?: number,
): Promise<string> {
  return createEthrJwt(identity.did, identity.privateKeyHex, payload, expiresIn);
}

export interface Passkey {
  did: string;
  publicKeyCose: Uint8Array;
  privateKey: CryptoKey;
}

export async function newPasskey(): Promise<Passkey> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  // COSE_Key bytes as an authenticator writes them: a CBOR map of
  // 1 (kty): 2 (EC2), 3 (alg): -7 (ES256), -1 (crv): 1 (P-256), -2: x, -3: y
  const publicKeyCose = isoUint8ArrayConcat([
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    new Uint8Array(Buffer.from(jwk.x!, "base64url")),
    new Uint8Array([0x22, 0x58, 0x20]),
    new Uint8Array(Buffer.from(jwk.y!, "base64url")),
  ]);
  return { did: createPeerDid(publicKeyCose), publicKeyCose, privateKey: keyPair.privateKey };
}

/** DER-encode a raw r || s signature the way an authenticator returns it. */
export function derEncodeSignature(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let body = bytes.subarray(start);
    if (body[0] & 0x80) body = isoUint8ArrayConcat([new Uint8Array([0]), body]);
    return isoUint8ArrayConcat([new Uint8Array([0x02, body.length]), body]);
  };
  const r = integer(raw.subarray(0, 32));
  const s = integer(raw.subarray(32, 64));
  return isoUint8ArrayConcat([new Uint8Array([0x30, r.length + s.length]), r, s]);
}

export interface JwantOptions {
  /** epoch seconds for "exp"; default 60 seconds from now */
  exp?: number;
  /** keep signing until r or s has a leading zero byte, so its DER form is short */
  requireShortComponent?: boolean;
  /** change the claim after signing */
  tamper?: boolean;
  /** put this issuer DID in the token while signing with the passkey's own key */
  claimedDid?: string;
}

export async function passkeyJwt(
  passkey: Passkey,
  claim: Record<string, unknown>,
  {
    exp = epochNow() + 60,
    requireShortComponent = false,
    tamper = false,
    claimedDid = passkey.did,
  }: JwantOptions = {},
): Promise<string> {
  const iat = epochNow();
  const fullPayload = { ...claim, exp, iat, iss: claimedDid };
  const clientDataJSON = JSON.stringify({
    type: "webauthn.get",
    challenge: base64urlEncodeString(JSON.stringify(fullPayload)),
    origin: "https://test.example",
    crossOrigin: false,
  });
  const clientDataBytes = new TextEncoder().encode(clientDataJSON);
  // rpIdHash (32) || flags (1) || signCount (4)
  const authenticatorData = isoUint8ArrayConcat([
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("test.example"))),
    new Uint8Array([0x05, 0, 0, 0, 0]),
  ]);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataBytes));
  const preimage = isoUint8ArrayConcat([authenticatorData, clientDataHash]);

  let raw: Uint8Array;
  for (;;) {
    raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.privateKey, new Uint8Array(preimage)),
    );
    if (!requireShortComponent || raw[0] === 0 || raw[32] === 0) break;
  }

  const finalClientData = tamper
    ? clientDataJSON.replace(
        base64urlEncodeString(JSON.stringify(fullPayload)),
        base64urlEncodeString(JSON.stringify({ ...fullPayload, tampered: true })),
      )
    : clientDataJSON;
  const header = { typ: "JWANT", alg: "ES256" };
  const payload = {
    AuthenticationDataB64URL: bytesToBase64Url(authenticatorData),
    ClientDataJSONB64URL: base64urlEncodeString(finalClientData),
    exp,
    iat,
    iss: claimedDid,
  };
  return (
    base64urlEncodeString(JSON.stringify(header)) +
    "." +
    base64urlEncodeString(JSON.stringify(payload)) +
    "." +
    bytesToBase64Url(derEncodeSignature(raw))
  );
}
