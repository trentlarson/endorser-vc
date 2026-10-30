/**
 * Byte and base64url helpers that work the same in Node and browsers, so no
 * caller needs a Buffer polyfill.
 */

import { base64ToBytes, bytesToBase64url } from "did-jwt";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return textDecoder.decode(b);
}

/** Accepts base64url or standard base64, with or without padding. */
export function base64urlToBytes(s: string): Uint8Array {
  return base64ToBytes(s);
}

/** Unpadded base64url. */
export function bytesToBase64Url(b: Uint8Array): string {
  return bytesToBase64url(b);
}

export function base64urlDecodeString(s: string): string {
  return bytesToUtf8(base64urlToBytes(s));
}

export function base64urlEncodeString(s: string): string {
  return bytesToBase64Url(utf8ToBytes(s));
}

/** Convert standard base64 to unpadded base64url. */
export function toBase64Url(anythingB64: string): string {
  return anythingB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// from https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/iso/isoUint8Array.ts#L49
/** Combine multiple Uint8Arrays into a single Uint8Array. */
export function isoUint8ArrayConcat(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);
  const toReturn = new Uint8Array(totalLength);
  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });
  return toReturn;
}

/** WebCrypto: global in browsers and in Node 19+. */
export function getSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "WebCrypto (globalThis.crypto.subtle) is not available; use Node 20+ or a modern browser.",
    );
  }
  return subtle;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await getSubtleCrypto().digest("SHA-256", new Uint8Array(data)));
}
