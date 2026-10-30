/**
 * Verifiable Credential & DID functions for Endorser Search tools: verify and
 * create the did:ethr and did:peer (passkey) JWTs they exchange.
 */

export * from "./constants";
export {
  base64urlDecodeString,
  base64urlEncodeString,
  base64urlToBytes,
  bytesToBase64Url,
  isoUint8ArrayConcat,
  toBase64Url,
} from "./bytes";
export { didEthLocalResolver } from "./didEthLocalResolver";
export {
  cborToKeys,
  createPeerDid,
  peerDidToPublicKeyBytes,
  unwrapEC2Signature,
  verifyPeerSignature,
  type PublicKeyJwk,
} from "./didPeer";
export {
  isClientErrorRejection,
  type ClientErrorRejection,
  type JwtPayload,
} from "./errors";
export { verifyPasskeyJwt, type PasskeyJwtOptions } from "./passkeyJwt";
export { createDidPeerJwt, type PasskeyJwtCreateOptions } from "./passkeyBrowser";
export {
  createEndorserJwtForKey,
  createEthrJwt,
  decodeEndorserJwt,
  isFromPasskey,
  SimpleSigner,
  type SigningAccount,
} from "./sign";
export {
  createVerifier,
  decodeAndVerifyDelegatedJwt,
  decodeAndVerifyJwt,
  identitySupportsDelegatedJwtBatch,
  type Logger,
  type VerifiedJwt,
  type Verifier,
  type VerifierOptions,
  type VerifyOptions,
} from "./verify";
