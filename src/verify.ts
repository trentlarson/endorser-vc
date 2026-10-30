import { verifyJWT, type JWTVerified, type JWTVerifyOptions } from "did-jwt";
import { Resolver } from "did-resolver";

import { base64urlDecodeString } from "./bytes";
import {
  DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE,
  ETHR_DID_PREFIX,
  INVALID_AUDIENCE_CODE,
  JWANT_TYP,
  JWT_VERIFY_FAILED_CODE,
  PEER_DID_PREFIX,
  UNSUPPORTED_DID_METHOD_CODE,
} from "./constants";
import { didEthLocalResolver } from "./didEthLocalResolver";
import { clientErrorRejection, type ClientErrorRejection, type JwtPayload } from "./errors";
import { verifyPasskeyJwt } from "./passkeyJwt";

export interface Logger {
  warn(message: string): void;
  info?(message: string): void;
}

export interface VerifierOptions {
  /**
   * Identifies this deployment when a client binds a credential to it with "aud".
   * Any agreed string works: it is compared for equality. Leave it unset to ignore
   * "aud" entirely, which lets clients adopt the field before a deployment enforces it.
   */
  audience?: string;
  /**
   * Reject a credential without "aud" (when checkAudience is requested and an
   * audience is set). Turn this on once every client sends "aud"; until then a
   * missing "aud" is accepted and reported through the logger.
   */
  requireAudience?: boolean;
  /** Receives the periodic report of credentials without "aud". Default: no logging. */
  logger?: Logger;
  /** How often to report credentials without "aud". Default: one hour. */
  unaudiencedLogIntervalMs?: number;
  /**
   * Accept expired did:peer (passkey) tokens. Test fixtures need this because
   * they can't be re-signed without a real authenticator. Never set it in production.
   */
  testOnlySkipPeerExpiry?: boolean;
  /**
   * Accept any did:ethr token without checking its signature, and move an
   * expired "exp" to 100 seconds from now. Never set it in production.
   */
  testOnlySkipEthrVerification?: boolean;
}

export interface VerifyOptions {
  /**
   * Apply the audience rules. Pass true on the credential path; claims are
   * portable by design and carry no audience, so verify them without it.
   */
  checkAudience?: boolean;
}

/**
 * A successful verification. Every token that fails verification rejects with
 * a ClientErrorRejection instead, so "verified" is always true here.
 *
 * For did:ethr, the other did-jwt JWTVerified fields (didResolutionResult,
 * signer, jwt, policies) are present too.
 */
export interface VerifiedJwt
  extends Partial<Omit<JWTVerified, "issuer" | "payload" | "verified">> {
  issuer: string;
  payload: JwtPayload;
  verified: true;
}

export interface Verifier {
  decodeAndVerifyJwt(jwt: string, options?: VerifyOptions): Promise<VerifiedJwt>;
  /**
   * Verify a pre-issued delegated JWT, where a future "nbf" is expected.
   * Passkey (did:peer / JWANT) tokens are refused with
   * DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE because each needs a live assertion.
   */
  decodeAndVerifyDelegatedJwt(jwt: string, options?: VerifyOptions): Promise<VerifiedJwt>;
}

const resolver = new Resolver({ ethr: didEthLocalResolver });

// Cap the sample: a caller can mint unlimited DIDs, so this must not grow with them.
const UNAUDIENCED_SAMPLE_MAX = 20;

function parseJwt(
  jwt: string,
): { header: JwtPayload; payload: JwtPayload; signature: string } | undefined {
  const pieces = jwt.split(".");
  if (pieces.length !== 3 || pieces[0].length === 0 || pieces[1].length === 0) {
    return undefined;
  }
  try {
    const header = JSON.parse(base64urlDecodeString(pieces[0]));
    const payload = JSON.parse(base64urlDecodeString(pieces[1]));
    if (typeof header !== "object" || header === null || typeof payload !== "object" || payload === null) {
      return undefined;
    }
    return { header, payload, signature: pieces[2] };
  } catch {
    return undefined;
  }
}

function epochNow(): number {
  return Math.floor(Date.now() / 1000);
}

export function identitySupportsDelegatedJwtBatch(did: string): boolean {
  return did.startsWith(ETHR_DID_PREFIX);
}

export function createVerifier(options: VerifierOptions = {}): Verifier {
  const {
    audience,
    requireAudience = false,
    logger,
    unaudiencedLogIntervalMs = 60 * 60 * 1000,
    testOnlySkipPeerExpiry = false,
    testOnlySkipEthrVerification = false,
  } = options;

  let unaudiencedCount = 0;
  let unaudiencedIssuers = new Set<string>();
  let unaudiencedWindowStart = Date.now();

  // Reporting on credentials that arrive without an "aud", so that the switch
  // to requireAudience can wait until this goes quiet.
  function noteUnaudiencedCredential(issuerDid: unknown) {
    unaudiencedCount += 1;
    if (unaudiencedIssuers.size < UNAUDIENCED_SAMPLE_MAX) {
      unaudiencedIssuers.add(String(issuerDid));
    }
    const now = Date.now();
    if (now - unaudiencedWindowStart < unaudiencedLogIntervalMs) {
      return;
    }
    const sample = Array.from(unaudiencedIssuers);
    const truncated = unaudiencedIssuers.size >= UNAUDIENCED_SAMPLE_MAX ? " (sample truncated)" : "";
    logger?.warn(
      `Credentials without "aud": ${unaudiencedCount} in the last ` +
        `${Math.round((now - unaudiencedWindowStart) / 60000)} minutes, from issuers ` +
        `${sample.join(", ")}${truncated}. ` +
        `Require an audience once this stops appearing.`,
    );
    unaudiencedCount = 0;
    unaudiencedIssuers = new Set();
    unaudiencedWindowStart = now;
  }

  /**
   * Audience rules, applied only when the caller asks (the credential path):
   *
   * - no audience configured: "aud" is ignored. Note that did-jwt's own default
   *   is to *reject* any JWT carrying "aud" when no audience is configured, which
   *   would break clients that adopt the field first, so it is disabled.
   * - configured: a mismatched "aud" is rejected; a missing one is accepted
   *   unless requireAudience is set.
   */
  function audienceError(payload: JwtPayload, enforcing: boolean): ClientErrorRejection["clientError"] | null {
    if (!enforcing) {
      return null;
    }
    if (!payload.aud) {
      if (requireAudience) {
        return { message: `JWT is missing the "aud" field.`, code: INVALID_AUDIENCE_CODE };
      }
      noteUnaudiencedCredential(payload.iss);
      return null;
    }
    const audArray = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    return audArray.includes(audience)
      ? null
      : { message: `JWT "aud" does not name this service.`, code: INVALID_AUDIENCE_CODE };
  }

  async function verifyEthr(
    jwt: string,
    issuerDid: string,
    payload: JwtPayload,
    enforcingAudience: boolean,
    policies: JWTVerifyOptions["policies"],
    moveExpiredInTestMode: boolean,
  ): Promise<VerifiedJwt> {
    if (testOnlySkipEthrVerification) {
      if (moveExpiredInTestMode) {
        const nowEpoch = epochNow();
        if (typeof payload.exp === "number" && payload.exp < nowEpoch) {
          logger?.info?.(
            `JWT with exp ${payload.exp} has expired but we're in test mode so we'll use a new time.`,
          );
          payload.exp = nowEpoch + 100;
        }
      }
      const audFailure = audienceError(payload, enforcingAudience);
      if (audFailure) {
        return Promise.reject({ clientError: audFailure });
      }
      return { issuer: issuerDid, payload, verified: true };
    }

    let verifiedResult: JWTVerified;
    try {
      const verifyOptions: JWTVerifyOptions = enforcingAudience
        // did-jwt tolerates a missing "aud"; audienceError decides on that case.
        ? { resolver, audience, policies }
        // Disable did-jwt's audience handling so a credential carrying "aud"
        // is not rejected merely because this deployment has none configured.
        : { resolver, policies: { ...policies, aud: false } };
      verifiedResult = await verifyJWT(jwt, verifyOptions);
    } catch (e) {
      // did-jwt raises its own audience mismatch before audienceError runs, and
      // labels it with a generic code, so surface it as an audience problem to
      // give a client something actionable when its "aud" is misconfigured.
      const isAudience = String(e).includes("audience");
      return clientErrorRejection(
        `JWT failed verification: ` + String(e),
        isAudience ? INVALID_AUDIENCE_CODE : JWT_VERIFY_FAILED_CODE,
      );
    }
    const audFailure = audienceError(verifiedResult.payload as JwtPayload, enforcingAudience);
    if (audFailure) {
      return Promise.reject({ clientError: audFailure });
    }
    return verifiedResult as VerifiedJwt;
  }

  async function decodeAndVerifyJwt(
    jwt: string,
    { checkAudience = false }: VerifyOptions = {},
  ): Promise<VerifiedJwt> {
    const enforcingAudience = checkAudience && !!audience;
    const parsed = parseJwt(jwt);
    if (!parsed) {
      return clientErrorRejection(
        `Error parsing JWT: it must be a header, payload, and signature, base64url-encoded.`,
        JWT_VERIFY_FAILED_CODE,
      );
    }
    const { header, payload, signature } = parsed;
    const issuerDid = payload.iss;
    if (!issuerDid || typeof issuerDid !== "string") {
      return clientErrorRejection(`Missing "iss" field in JWT.`, JWT_VERIFY_FAILED_CODE);
    }

    if (issuerDid.startsWith(ETHR_DID_PREFIX)) {
      return verifyEthr(jwt, issuerDid, payload, enforcingAudience, undefined, true);
    }

    if (issuerDid.startsWith(PEER_DID_PREFIX) && header.typ === JWANT_TYP) {
      const claimPayload = await verifyPasskeyJwt(payload, issuerDid, signature, {
        skipExpiry: testOnlySkipPeerExpiry,
      });
      // verifyPasskeyJwt does not inspect "aud", so without this the did:peer
      // path would be an audience-check bypass.
      const audFailure = audienceError(claimPayload, enforcingAudience);
      if (audFailure) {
        return Promise.reject({ clientError: audFailure });
      }
      return { issuer: issuerDid, payload: claimPayload, verified: true };
    }

    if (issuerDid.startsWith(PEER_DID_PREFIX)) {
      return clientErrorRejection(
        `JWT with a PEER DID currently only supported with typ == JWANT. Contact us for JWT support since it should be straightforward.`,
        JWT_VERIFY_FAILED_CODE,
      );
    }

    return clientErrorRejection(`Unsupported DID method ${issuerDid}`, UNSUPPORTED_DID_METHOD_CODE);
  }

  async function decodeAndVerifyDelegatedJwt(
    jwt: string,
    { checkAudience = false }: VerifyOptions = {},
  ): Promise<VerifiedJwt> {
    const enforcingAudience = checkAudience && !!audience;
    const parsed = parseJwt(jwt);
    if (!parsed) {
      return clientErrorRejection("Delegated credential is not a valid JWT.", JWT_VERIFY_FAILED_CODE);
    }
    const { header, payload } = parsed;
    const issuerDid = payload.iss;
    if (!issuerDid || typeof issuerDid !== "string") {
      return clientErrorRejection(`Missing "iss" field in JWT.`, JWT_VERIFY_FAILED_CODE);
    }

    if (issuerDid.startsWith(PEER_DID_PREFIX) || header.typ === JWANT_TYP) {
      return clientErrorRejection(
        "This identity type cannot mint a delegated JWT batch. Passkey (did:peer / JWANT) credentials require a live assertion and cannot be pre-issued for future days.",
        DELEGATED_JWT_UNSUPPORTED_IDENTITY_CODE,
      );
    }

    if (issuerDid.startsWith(ETHR_DID_PREFIX)) {
      return verifyEthr(jwt, issuerDid, payload, enforcingAudience, { nbf: false }, false);
    }

    return clientErrorRejection(`Unsupported DID method ${issuerDid}`, UNSUPPORTED_DID_METHOD_CODE);
  }

  return { decodeAndVerifyJwt, decodeAndVerifyDelegatedJwt };
}

const defaultVerifier = createVerifier();

/** Verify with the defaults: no audience, no test bypasses. See createVerifier. */
export const decodeAndVerifyJwt = defaultVerifier.decodeAndVerifyJwt;
/** Verify with the defaults: no audience, no test bypasses. See createVerifier. */
export const decodeAndVerifyDelegatedJwt = defaultVerifier.decodeAndVerifyDelegatedJwt;
