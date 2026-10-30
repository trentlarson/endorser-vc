import { base64urlToBytes, bytesToUtf8, isoUint8ArrayConcat, sha256 } from "./bytes";
import { JWT_VERIFY_FAILED_CODE } from "./constants";
import { peerDidToPublicKeyBytes, verifyPeerSignature } from "./didPeer";
import { clientErrorRejection, type JwtPayload } from "./errors";

export interface PasskeyJwtOptions {
  /** Epoch seconds; defaults to the clock. */
  nowEpoch?: number;
  /** Accept an expired token. For test fixtures, which can't be re-signed without a real authenticator. */
  skipExpiry?: boolean;
}

/**
 * Verify a JWANT: a JWT-shaped token from a passkey (WebAuthn) assertion.
 *
 * The payload carries the WebAuthn AuthenticationData and ClientDataJSON, and the
 * signature covers authenticatorData || sha256(clientDataJSON). The claim itself
 * travels as the WebAuthn challenge inside ClientDataJSON.
 *
 * Not checked: the clientData "type" and "origin" and the rpIdHash in the
 * authenticator data, since one did:peer is accepted by every deployment.
 *
 * @returns the claim payload from the challenge; rejects with { clientError } on any failure,
 *   including a bad signature
 */
export async function verifyPasskeyJwt(
  payload: JwtPayload,
  issuerDid: string,
  signatureString: string,
  { nowEpoch = Math.floor(Date.now() / 1000), skipExpiry = false }: PasskeyJwtOptions = {},
): Promise<JwtPayload> {
  if (!payload.iss) {
    return clientErrorRejection(`JWT is missing an "iss" field.`, JWT_VERIFY_FAILED_CODE);
  }
  if (typeof payload.exp !== "number") {
    return clientErrorRejection(`JWT is missing a numeric "exp" field.`, JWT_VERIFY_FAILED_CODE);
  }
  if (payload.exp < nowEpoch && !skipExpiry) {
    return clientErrorRejection(`JWT with exp ${payload.exp} has expired.`, JWT_VERIFY_FAILED_CODE);
  }

  const authData = payload.AuthenticationDataB64URL;
  const clientData = payload.ClientDataJSONB64URL;
  if (typeof authData !== "string" || typeof clientData !== "string") {
    return clientErrorRejection(
      `JWT with typ == JWANT requires AuthenticationData and ClientDataJSON.`,
      JWT_VERIFY_FAILED_CODE,
    );
  }

  let decodedAuthData: Uint8Array, decodedClientData: Uint8Array, claimPayload: JwtPayload;
  try {
    decodedAuthData = base64urlToBytes(authData);
    decodedClientData = base64urlToBytes(clientData);
    claimPayload = JSON.parse(bytesToUtf8(decodedClientData));
    if (claimPayload.challenge) {
      claimPayload = JSON.parse(bytesToUtf8(base64urlToBytes(claimPayload.challenge as string)));
      if (!claimPayload.exp) {
        claimPayload.exp = payload.exp;
      }
      if (!claimPayload.iat) {
        claimPayload.iat = payload.iat;
      }
      if (!claimPayload.iss) {
        claimPayload.iss = payload.iss;
      }
    }
  } catch (e) {
    return clientErrorRejection(
      `JWT client data could not be parsed: ${String(e)}`,
      JWT_VERIFY_FAILED_CODE,
    );
  }
  if (typeof claimPayload.exp !== "number") {
    return clientErrorRejection(
      `JWT client data challenge is missing a numeric "exp" field.`,
      JWT_VERIFY_FAILED_CODE,
    );
  }
  if (claimPayload.exp < nowEpoch && !skipExpiry) {
    return clientErrorRejection(`JWT client data challenge exp time is past.`, JWT_VERIFY_FAILED_CODE);
  }
  if (claimPayload.exp !== payload.exp) {
    return clientErrorRejection(
      `JWT client data challenge "exp" field doesn't match the outside payload "exp".`,
      JWT_VERIFY_FAILED_CODE,
    );
  }
  if (claimPayload.iss !== payload.iss) {
    return clientErrorRejection(
      `JWT client data challenge "iss" field doesn't match the outside payload "iss".`,
      JWT_VERIFY_FAILED_CODE,
    );
  }

  let verified: boolean;
  try {
    const hashedClientData = await sha256(decodedClientData);
    const preimage = isoUint8ArrayConcat([decodedAuthData, hashedClientData]);
    const publicKey = peerDidToPublicKeyBytes(issuerDid);
    const signature = base64urlToBytes(signatureString);
    verified = await verifyPeerSignature(preimage, publicKey, signature);
  } catch (e) {
    return clientErrorRejection(`JWT failed verification: ${String(e)}`, JWT_VERIFY_FAILED_CODE);
  }
  if (!verified) {
    return clientErrorRejection(`JWT signature failed verification.`, JWT_VERIFY_FAILED_CODE);
  }
  return claimPayload;
}
