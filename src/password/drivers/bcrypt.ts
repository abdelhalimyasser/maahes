/**
 * @fileoverview bcrypt driver.
 *
 * bcrypt is a well-established (1999) adaptive hashing algorithm with
 * wide ecosystem support and a hard 72-byte input limit. The driver
 * wraps the `bcrypt` npm package, validates the cost factor at
 * construction time and optionally pre-hashes inputs with SHA-256
 * (`preHash`) to eliminate the truncation limit.
 *
 * NOTE: when `preHash` is enabled the resulting hashes are NOT
 * interoperable with standard bcrypt hashes from other systems.
 *
 * @module password/drivers/bcrypt
 */

import bcrypt from "bcrypt";
import { createHash } from "node:crypto";
import { PasswordOptionsError } from "../config";
import type { BcryptOptions, PasswordDriver } from "../types";

/** Matches the leading cost segment of a bcrypt hash regardless of the variant prefix (2a/2b/2y/2x). */
const BCRYPT_HASH_RE = /^\$(?:2a|2b|2y|2x)\$(\d{2})\$/;

/**
 * Extracts the cost factor (rounds) from a stored bcrypt hash. Returns 0
 * for malformed or foreign hashes so they are always flagged for rehash.
 *
 * @param hash - A bcrypt hash string.
 * @returns The number of rounds encoded in the hash.
 */
function getRoundsFromHash(hash: string): number {
  const match = BCRYPT_HASH_RE.exec(hash);
  if (!match) return 0;
  const rounds = Number(match[1]);
  return Number.isFinite(rounds) ? rounds : 0;
}

/**
 * Validates bcrypt options.
 *
 * @param options - Driver options (defaults applied for missing fields).
 * @throws {PasswordOptionsError} When any option is out of range.
 */
export function validateBcryptOptions(options: BcryptOptions): void {
  const saltRounds = options.saltRounds ?? 12;

  if (!Number.isInteger(saltRounds) || saltRounds < 4 || saltRounds > 31) {
    throw new PasswordOptionsError(
      `bcrypt.saltRounds must be an integer between 4 and 31 (got ${saltRounds}).`
    );
  }
  if (options.preHash !== undefined && typeof options.preHash !== "boolean") {
    throw new PasswordOptionsError(`bcrypt.preHash must be a boolean (got ${options.preHash}).`);
  }
}

/**
 * Creates a bcrypt password driver.
 *
 * @param options - bcrypt tuning options; missing fields fall back to
 *   `saltRounds: 12`, `preHash: false`.
 * @returns A {@link PasswordDriver} implementation.
 * @throws {PasswordOptionsError} When options are invalid.
 */
export function createBcryptDriver(options: BcryptOptions = {}): PasswordDriver {
  validateBcryptOptions(options);

  const saltRounds = options.saltRounds ?? 12;
  const preHash = options.preHash ?? false;

  /** Prepares the input: optionally SHA-256 pre-hashed to defeat the 72-byte truncation limit. */
  const prepare = (password: string): string =>
    preHash ? createHash("sha256").update(password, "utf8").digest("hex") : password;

  return {
    /** Produces a salted bcrypt hash (`$2b$` format from the underlying library). */
    async hash(password: string): Promise<string> {
      return bcrypt.hash(prepare(password), saltRounds);
    },

    /** Returns `true` when the password matches; never throws on malformed hashes. */
    async verify(hash: string, password: string): Promise<boolean> {
      try {
        return await bcrypt.compare(prepare(password), hash);
      } catch {
        return false;
      }
    },

    /** Returns `true` when the hash uses a cost factor different from the current config. */
    async needsRehash(hash: string): Promise<boolean> {
      return getRoundsFromHash(hash) !== saltRounds;
    },
  };
}