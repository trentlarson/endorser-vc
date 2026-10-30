import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { decode as cborDecode } from "cbor-x";
import { bytesToMultibase, multibaseToBytes } from "did-jwt";

import { bytesToBase64Url, getSubtleCrypto, isoUint8ArrayConcat } from "./bytes";
import { PEER_DID_MULTIBASE_PREFIX } from "./constants";

export interface PublicKeyJwk {
  alg: string;
  crv: string;
  kty: string;
  x: string;
  y: string;
}

/**
 * Verify a WebAuthn ES256 (P-256) signature.
 *
 * @param payloadBytes the signed bytes; for WebAuthn that's authenticatorData || sha256(clientDataJSON)
 * @param publicKeyBytes the COSE-encoded public key, as stored in a did:peer:0 DID
 * @param signatureBytes the ASN.1 DER signature, as WebAuthn returns it
 */
export async function verifyPeerSignature(
  payloadBytes: Uint8Array,
  publicKeyBytes: Uint8Array,
  signatureBytes: Uint8Array,
): Promise<boolean> {
  const subtle = getSubtleCrypto();
  const finalSignature = unwrapEC2Signature(signatureBytes);
  const publicKeyJwk = cborToKeys(publicKeyBytes).publicKeyJwk;
  const publicKeyCryptoKey = await subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "ECDSA", namedCurve: publicKeyJwk.crv },
    false,
    ["verify"],
  );
  return subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKeyCryptoKey,
    new Uint8Array(finalSignature),
    new Uint8Array(payloadBytes),
  );
}

/** Extract a P-256 public key from its COSE (CBOR) encoding. */
export function cborToKeys(publicKeyBytes: Uint8Array): {
  publicKeyJwk: PublicKeyJwk;
  publicKeyBuffer: Uint8Array;
} {
  const jwkObj = cborDecode(publicKeyBytes) as Record<number, unknown>;
  const x = jwkObj[-2];
  const y = jwkObj[-3];
  if (
    jwkObj[1] != 2 || // kty "EC"
    jwkObj[3] != -7 || // alg "ES256"
    jwkObj[-1] != 1 || // crv "P-256"
    !(x instanceof Uint8Array) ||
    x.length != 32 ||
    !(y instanceof Uint8Array) ||
    y.length != 32
  ) {
    throw new Error("Unable to extract key.");
  }
  const publicKeyJwk = {
    alg: "ES256",
    crv: "P-256",
    kty: "EC",
    x: bytesToBase64Url(x),
    y: bytesToBase64Url(y),
  };
  const publicKeyBuffer = isoUint8ArrayConcat([x, y]);
  return { publicKeyJwk, publicKeyBuffer };
}

/** @returns the COSE-encoded public key inside a did:peer:0 DID */
export function peerDidToPublicKeyBytes(did: string): Uint8Array {
  return multibaseToBytes(did.substring(PEER_DID_MULTIBASE_PREFIX.length));
}

/** @param publicKeyBytes COSE-encoded public key, eg. a WebAuthn credentialPublicKey */
export function createPeerDid(publicKeyBytes: Uint8Array): string {
  // https://github.com/decentralized-identity/veramo/blob/next/packages/did-provider-peer/src/peer-did-provider.ts#L67
  const methodSpecificId = bytesToMultibase(
    publicKeyBytes,
    "base58btc",
    "p256-pub",
  );
  return PEER_DID_MULTIBASE_PREFIX + methodSpecificId;
}

const P256_COMPONENT_LENGTH = 32;

// adapted from https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/iso/isoCrypto/unwrapEC2Signature.ts
/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 *
 * @return the raw P-256 r || s signature, 64 bytes
 */
export function unwrapEC2Signature(signature: Uint8Array): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  const rBytes = toFixedLength(new Uint8Array(parsedSignature.r));
  const sBytes = toFixedLength(new Uint8Array(parsedSignature.s));
  return isoUint8ArrayConcat([rBytes, sBytes]);
}

/**
 * DER integers are minimal-length and signed: a value with its high bit set
 * gains a leading 0x00, and a value with leading zero bytes loses them. WebCrypto
 * wants each component at exactly the curve size, so strip or left-pad to that.
 */
function toFixedLength(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (bytes.length - start > P256_COMPONENT_LENGTH && bytes[start] === 0x0) {
    start++;
  }
  const trimmed = bytes.subarray(start);
  if (trimmed.length > P256_COMPONENT_LENGTH) {
    throw new Error("Signature component is too long for P-256.");
  }
  const result = new Uint8Array(P256_COMPONENT_LENGTH);
  result.set(trimmed, P256_COMPONENT_LENGTH - trimmed.length);
  return result;
}
