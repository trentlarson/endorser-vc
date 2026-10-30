export const ETHR_DID_PREFIX = "did:ethr:";
export const PEER_DID_PREFIX = "did:peer:";
/** did:peer numalgo 0: the rest of the DID is the multibase-encoded public key. */
export const PEER_DID_MULTIBASE_PREFIX = PEER_DID_PREFIX + "0";

/** The JWT typ for a passkey-signed token; see verifyPasskeyJwt. */
export const JWANT_TYP = "JWANT";

/**
 * Error codes, found at `clientError.code` on a rejection. Clients match on
 * these strings, so changing one is a breaking change.
 */
export const JWT_VERIFY_FAILED_CODE = "JWT_VERIFY_FAILED";
export const UNSUPPORTED_DID_METHOD_CODE = "UNSUPPORTED_DID_METHOD";
export const INVALID_AUDIENCE_CODE = "INVALID_AUDIENCE";
export const DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE =
  "DELEGATED_JWT_UNSUPPORTED_IDENTITY";
