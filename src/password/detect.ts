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
 * The pepper marker embeds the id of the secret that produced the hash
 * (see {@link PepperKey}), so verification can select the exact secret
 * from the configured keyring — this is what makes real pepper rotation
 * possible. Detection makes multi-algorithm migration straightforward
 * (e.g. deciding which driver must verify a legacy hash).
 *
 * @module password/detect
 */

import { createHash } from "node:crypto";
import type { PasswordAlgorithm } from "./types";

/** Leading marker segment for peppered hashes. */
const MARKER_PREFIX = "$pepper$";
/** Length of a derived (legacy string-form) pepper id in characters. */
const DERIVED_ID_LENGTH = 8;
/**
 * Matches a well-formed peppered hash: `$pepper$<id>$<inner>` where the
 * id is 1–32 chars of letters, digits, `_` or `-`. Legacy derived ids
 * (8 lowercase hex chars) are a subset and keep working.
 */
const PEPPERED_HASH_RE = /^\$pepper\$[A-Za-z0-9_-]{1,32}\$/;
/** Matches a valid pepper id in isolation (validation / tooling). */
const PEPPER_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

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
 * Returns `true` when `id` is a valid pepper id (1–32 chars of letters,
 * digits, `_` or `-`).
 *
 * @param id - The candidate pepper id.
 * @returns `true` when the id is well-formed.
 */
export function isValidPepperId(id: string): boolean {
  return PEPPER_ID_RE.test(id);
}

/**
 * Extracts the pepper id embedded in a marked hash.
 *
 * @param hash - A stored password hash.
 * @returns The pepper id, or `null` when the hash is not marked.
 */
export function extractPepperId(hash: string): string | null {
  const match = /^\$pepper\$([A-Za-z0-9_-]{1,32})\$/.exec(hash);
  return match ? match[1] : null;
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
 * Derives a stable short identifier for a pepper secret by hashing it
 * with SHA-256. Used for the legacy string-form pepper configuration,
 * whose markers embed this derived id.
 *
 * The id reveals nothing about the secret itself (preimage resistance)
 * and is safe to store next to hashes.
 *
 * @param pepper - The configured pepper secret.
 * @returns The leading 8 hex characters of SHA-256(`pepper`).
 */
export function pepperId(pepper: string): string {
  return createHash("sha256").update(pepper, "utf8").digest("hex").slice(0, DERIVED_ID_LENGTH);
}

/**
 * Wraps an already-hashed inner hash in the pepper marker, embedding the
 * given pepper id for later verification and rotation.
 *
 * @param id - The pepper id that produced `innerHash` (current or previous).
 * @param innerHash - An algorithm-native hash string.
 * @returns `$pepper$<id>$<innerHash>`.
 */
export function wrapPepperMarker(id: string, innerHash: string): string {
  return `${MARKER_PREFIX}${id}$${innerHash}`;
}