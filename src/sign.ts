import {
  base64ToBytes,
  bytesToHex,
  createJWT,
  decodeJWT,
  ES256KSigner,
  hexToBytes,
  type JWTPayload,
  type Signer,
} from "did-jwt";

import { createDidPeerJwt } from "./passkeyBrowser";

/** The parts of a stored identity needed to sign; matches Time Safari's KeyMeta. */
export interface SigningAccount {
  did: string;
  /** Stringified Veramo IIdentifier, holding keys[0].privateKeyHex */
  identity?: string;
  /** The WebAuthn credential ID in hex, if this is from a passkey */
  passkeyCredIdHex?: string;
}

/**
 * Tell whether a key is from a passkey
 * @param keyMeta contains info about the key, whose passkeyCredIdHex determines if the key is from a passkey
 */
export function isFromPasskey(keyMeta?: { passkeyCredIdHex?: string }): boolean {
  return !!keyMeta?.passkeyCredIdHex;
}

/**
 * Sign a JWT with the account's key: secp256k1 for an identity with a private
 * key, or a passkey assertion (browser only) for a passkey account.
 */
export async function createEndorserJwtForKey(
  account: SigningAccount,
  payload: Partial<JWTPayload>,
  expiresIn?: number,
): Promise<string> {
  if (account?.identity) {
    const identity = JSON.parse(account.identity) as {
      keys: Array<{ privateKeyHex?: string }>;
    };
    const privateKeyHex = identity.keys[0]?.privateKeyHex;
    if (!privateKeyHex) {
      throw new Error("No private key found in the identity for DID " + account.did);
    }
    return createEthrJwt(account.did, privateKeyHex, payload, expiresIn);
  } else if (account?.passkeyCredIdHex) {
    return createDidPeerJwt(account.did, account.passkeyCredIdHex, payload);
  } else {
    throw new Error("No identity data found to sign for DID " + account?.did);
  }
}

/** Sign an ES256K JWT for a did:ethr issuer. */
export async function createEthrJwt(
  issuerDid: string,
  privateKeyHex: string,
  payload: Partial<JWTPayload>,
  expiresIn?: number,
): Promise<string> {
  return createJWT(payload, {
    issuer: issuerDid,
    signer: SimpleSigner(privateKeyHex),
    ...(expiresIn ? { expiresIn } : {}),
  });
}

/**
 *  Copied out of did-jwt since it's deprecated in that library.
 *
 *  The signer returns { r, s, recoveryParam } rather than a JOSE string so that
 *  did-jwt's ES256K algorithm drops the recovery byte, producing the 64-byte
 *  signatures that existing clients send.
 *
 *  @param hexPrivateKey a hex encoded private key
 */
export function SimpleSigner(hexPrivateKey: string): Signer {
  const signer = ES256KSigner(hexToBytes(hexPrivateKey), true);
  return async (data) => {
    const signature = (await signer(data)) as string;
    return fromJose(signature);
  };
}

// from did-jwt/util; see SimpleSigner above
function fromJose(signature: string): {
  r: string;
  s: string;
  recoveryParam?: number;
} {
  const signatureBytes: Uint8Array = base64ToBytes(signature);
  if (signatureBytes.length < 64 || signatureBytes.length > 65) {
    throw new TypeError(
      `Wrong size for signature. Expected 64 or 65 bytes, but got ${signatureBytes.length}`,
    );
  }
  const r = bytesToHex(signatureBytes.slice(0, 32));
  const s = bytesToHex(signatureBytes.slice(32, 64));
  const recoveryParam = signatureBytes.length === 65 ? signatureBytes[64] : undefined;
  return { r, s, recoveryParam };
}

/**
 * Decode without verifying the signature.
 * @returns JWTDecoded with { header, payload, signature, data }
 */
export function decodeEndorserJwt(jwt: string): ReturnType<typeof decodeJWT> {
  return decodeJWT(jwt);
}
