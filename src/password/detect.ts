/**
 * @fileoverview Hash format detection and pepper-marker utilities.
 *
 * The password module stores three standardized hash shapes, plus an
 * optional pepper marker wrapping any of them:
 *
 * - Argon2:   `$argon2id$v=19$...`
 * - bcrypt:   `$2a$/$2b$/$2y$/$2x$10$...`
 * - scrypt:   `$scrypt$N=16384$r=8$p=1$<salt>$<hash>`
 * - Peppered: `$pepper$<id>$<inner-hash>` (any of the above wrapped)
 *
 * Detection makes multi-algorithm migration straighforward (e.g. deciding
 * which driver must verify a legacy hash), and the pepper marker lets
 * `verifyPassword` transparently apply the configured pepper.
 *
 * @module password/detect
 */

import { createHash } from "node:crypto";
import type { PasswordAlgorithm } from "./types";

/** Leading marker segment for peppered hashes. */
const MARKER_PREFIX = "$pepper$";
/** Length of the pepper identifier in characters. */
const PEPPER_ID_LENGTH = 8;
/** Matches a well-formed peppered hash: `$pepper$<8-hex-id>$<inner>`. */
const PEPPERED_HASH_RE = /^\$pepper\$[0-9a-f]{8}\$/;

/**
 * Returns `true` when `hash` carries the pepper marker, i.e. its inner
 * payload was mixed with a site pepper via HMAC-SHA256 before hashing.
 *
 * @param hash - A stored password hash.
 * @returns `true` when the pepper marker is present.
 */
export function isPepperedHash(hash: string): boolean {
  return PEPPERED_HASH_RE.test(hash);
}

/**
 * Removes the pepper marker from a hash, returning the inner (algorithm
 * native) hash string. Non-marked hashes pass through unchanged.
 *
 * @param hash - A stored password hash (marked or not).
 * @returns The inner hash without the pepper wrapper.
 */
export function stripPepperMarker(hash: string): string {
  if (!isPepperedHash(hash)) return hash;
  return hash.split("$").slice(3).join("$");
}

/**
 * Detects the algorithm that produced a stored hash by inspecting its
 * encoding. Pepper-marked hashes are unwrapped first, so detection works
 * on every format the module can write.
 *
 * @param hash - A stored password hash (any supported algorithm, marked or not).
 * @returns The detected algorithm, or `null` for unrecognized formats.
 */
export function detectHashAlgorithm(hash: string): PasswordAlgorithm | null {
  const inner = stripPepperMarker(hash);

  if (/^\$argon2(?:i|d|id)\$/.test(inner)) return "argon2";
  if (/^\$(?:2a|2b|2y|2x)\$/.test(inner)) return "bcrypt";
  if (/^\$scrypt\$N=/.test(inner)) return "scrypt";

  return null;
}

/**
 * Internal: derives a stable short identifier for a pepper secret by
 * hashing it with SHA-256. The identifier is embedded in the pepper
 * marker so the exact secret used can be identified later (pepper rotation).
 *
 * @param pepper - The configured pepper secret.
 * @returns The leading 8 hex characters of SHA-256(`pepper`).
 */
export function pepperId(pepper: string): string {
  return createHash("sha256").update(pepper, "utf8").digest("hex").slice(0, PEPPER_ID_LENGTH);
}

/**
 * Internal: wraps an already-hashed inner hash in the pepper marker,
 * embedding the pepper identifier for later verification and rotation.
 *
 * @param pepper - The configured pepper secret.
 * @param innerHash - An algorithm-native hash string.
 * @returns `$pepper$<id>$<innerHash>`.
 */
export function wrapPepperMarker(pepper: string, innerHash: string): string {
  return `${MARKER_PREFIX}${pepperId(pepper)}$${innerHash}`;
}