/**
 * Passkey signing through the browser's WebAuthn API (navigator.credentials).
 * These functions only work in a browser with an authenticator; nothing here
 * touches browser globals until called, so importing it elsewhere is safe.
 */

import { base64urlEncodeString, bytesToBase64Url } from "./bytes";
import { JWANT_TYP } from "./constants";

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

export interface PasskeyJwtCreateOptions {
  /** Minutes until "exp". Default: 1 */
  expMinutes?: number;
  /** WebAuthn relying party ID. Default: window.location.hostname */
  rpId?: string;
}

/**
 * Ask the authenticator to sign the payload, and package the assertion as a
 * JWANT: header { typ: "JWANT", alg: "ES256" }, a payload holding the WebAuthn
 * AuthenticationData and ClientDataJSON, and the WebAuthn signature. The full
 * payload is the WebAuthn challenge, so it ends up inside ClientDataJSON.
 */
export async function createDidPeerJwt(
  issuerDid: string,
  credIdHex: string,
  payload: object,
  { expMinutes = 1, rpId }: PasskeyJwtCreateOptions = {},
): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiryTime = issuedAt + expMinutes * 60;
  const fullPayload = {
    ...payload,
    exp: expiryTime,
    iat: issuedAt,
    iss: issuerDid,
  };
  const challenge = new TextEncoder().encode(JSON.stringify(fullPayload));

  const credential = (await navigator.credentials.get({
    publicKey: {
      allowCredentials: [
        {
          id: hexToArrayBuffer(credIdHex),
          type: "public-key",
        },
      ],
      challenge,
      rpId: rpId ?? window.location.hostname,
      userVerification: "preferred",
    },
  })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error("The authenticator returned no credential.");
  }
  const response = credential.response as AuthenticatorAssertionResponse;

  // Our custom type of JWANT means the signature is based on a concatenation of the two WebAuthn properties
  const header = { typ: JWANT_TYP, alg: "ES256" };
  const dataInJwt = {
    AuthenticationDataB64URL: bytesToBase64Url(new Uint8Array(response.authenticatorData)),
    ClientDataJSONB64URL: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    exp: expiryTime,
    iat: issuedAt,
    iss: issuerDid,
  };
  const signature = bytesToBase64Url(new Uint8Array(response.signature));

  return (
    base64urlEncodeString(JSON.stringify(header)) +
    "." +
    base64urlEncodeString(JSON.stringify(dataInJwt)) +
    "." +
    signature
  );
}
