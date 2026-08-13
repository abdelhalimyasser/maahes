/**
 * @fileoverview Argon2id driver.
 *
 * Argon2id is the default algorithm: it is memory-hard, side-channel
 * resistant and the current recommendation of OWASP and the IETF
 * (RFC 9106). This driver wraps the `argon2` npm package and supports its
 * full option set: memory/time cost, parallelism, key length, salt length
 * and version. Options are validated at construction time so misconfig
 * fails fast instead of surfacing mid-hash.
 *
 * DoS guard: construction-time caps bound how expensive a configuration
 * may be, and verification parses the PHC string of ANY stored hash and
 * rejects parameters beyond those caps BEFORE the native library is
 * invoked. This protects the login path from stored hashes crafted with
 * extreme parameters. See {@link ARGON2_MAX_MEMORY_COST}.
 *
 * @module password/drivers/argon2
 */

import * as argon2 from "argon2";
import { randomBytes } from "node:crypto";
import { PasswordOptionsError } from "../config";
import type { Argon2Options, PasswordDriver } from "../types";

/** Upper bound for `memoryCost` (KiB): 1 GiB — 16× the 64 MiB default. */
export const ARGON2_MAX_MEMORY_COST = 2 ** 20;
/** Upper bound for `timeCost`. */
export const ARGON2_MAX_TIME_COST = 32;
/** Upper bound for `parallelism`. */
export const ARGON2_MAX_PARALLELISM = 16;
/** Upper bound for `hashLength` (bytes). */
export const ARGON2_MAX_HASH_LENGTH = 256;
/** Upper bound for `saltLength` (bytes). */
export const ARGON2_MAX_SALT_LENGTH = 128;

/** Matches a PHC Argon2 string and captures its cost parameters. */
const ARGON2_PHC_RE =
  /^\$argon2(?:i|d|id)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=_-]{1,128})\$([A-Za-z0-9+/=_-]{1,344})$/;

/** Parsed cost parameters of a stored PHC hash. */
interface PhcParams {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

/**
 * Parses the cost parameters embedded in a stored Argon2 PHC string and
 * bounds its sections, so malformed or over-capped hashes are rejected
 * without invoking the native library.
 *
 * @param hash - A stored Argon2 PHC hash string.
 * @returns The parsed parameters, or `null` for malformed/oversized hashes.
 */
export function parsePhcParams(hash: string): PhcParams | null {
  const match = ARGON2_PHC_RE.exec(hash);
  if (!match) return null;
  return {
    memoryCost: Number(match[2]),
    timeCost: Number(match[3]),
    parallelism: Number(match[4]),
  };
}

/** `true` when the parsed parameters exceed the driver's caps. */
function exceedsCaps(params: PhcParams): boolean {
  return (
    params.memoryCost > ARGON2_MAX_MEMORY_COST ||
    params.timeCost > ARGON2_MAX_TIME_COST ||
    params.parallelism > ARGON2_MAX_PARALLELISM
  );
}

/**
 * Validates Argon2 options against the algorithm's hard constraints and
 * the driver's DoS caps.
 *
 * @param options - Driver options (defaults applied for missing fields).
 * @throws {PasswordOptionsError} When any option is out of range.
 */
export function validateArgon2Options(options: Argon2Options): void {
  const memoryCost = options.memoryCost ?? 2 ** 16;
  const timeCost = options.timeCost ?? 3;
  const parallelism = options.parallelism ?? 1;
  const hashLength = options.hashLength ?? 32;
  const saltLength = options.saltLength ?? 16;
  const version = options.version ?? 0x13;

  if (!Number.isInteger(parallelism) || parallelism < 1) {
    throw new PasswordOptionsError(`argon2.parallelism must be an integer >= 1 (got ${parallelism}).`);
  }
  if (parallelism > ARGON2_MAX_PARALLELISM) {
    throw new PasswordOptionsError(
      `argon2.parallelism must be <= ${ARGON2_MAX_PARALLELISM} (DoS guard, got ${parallelism}).`
    );
  }
  if (!Number.isInteger(memoryCost) || memoryCost < 8 * parallelism) {
    throw new PasswordOptionsError(
      `argon2.memoryCost must be an integer >= 8 * parallelism (${8 * parallelism}) (got ${memoryCost}).`
    );
  }
  if (memoryCost > ARGON2_MAX_MEMORY_COST) {
    throw new PasswordOptionsError(
      `argon2.memoryCost must be <= ${ARGON2_MAX_MEMORY_COST} KiB (DoS guard, got ${memoryCost}).`
    );
  }
  if (!Number.isInteger(timeCost) || timeCost < 1) {
    throw new PasswordOptionsError(`argon2.timeCost must be an integer >= 1 (got ${timeCost}).`);
  }
  if (timeCost > ARGON2_MAX_TIME_COST) {
    throw new PasswordOptionsError(
      `argon2.timeCost must be <= ${ARGON2_MAX_TIME_COST} (DoS guard, got ${timeCost}).`
    );
  }
  if (!Number.isInteger(hashLength) || hashLength < 4) {
    throw new PasswordOptionsError(`argon2.hashLength must be an integer >= 4 (got ${hashLength}).`);
  }
  if (hashLength > ARGON2_MAX_HASH_LENGTH) {
    throw new PasswordOptionsError(
      `argon2.hashLength must be <= ${ARGON2_MAX_HASH_LENGTH} (DoS guard, got ${hashLength}).`
    );
  }
  if (!Number.isInteger(saltLength) || saltLength < 8) {
    throw new PasswordOptionsError(`argon2.saltLength must be an integer >= 8 (got ${saltLength}).`);
  }
  if (saltLength > ARGON2_MAX_SALT_LENGTH) {
    throw new PasswordOptionsError(
      `argon2.saltLength must be <= ${ARGON2_MAX_SALT_LENGTH} (DoS guard, got ${saltLength}).`
    );
  }
  if (version !== 0x10 && version !== 0x13) {
    throw new PasswordOptionsError(`argon2.version must be 0x10 or 0x13 (got ${version}).`);
  }
}

/**
 * Creates an Argon2id password driver.
 *
 * The underlying library salts hashes with a random 16-byte salt; when a
 * custom `saltLength` is configured, this driver generates the salt
 * itself so the config surface stays complete.
 *
 * @param options - Argon2 tuning options; missing fields fall back to the
 *   documented defaults (false-fails fast on invalid ranges).
 * @returns A {@link PasswordDriver} implementation.
 * @throws {PasswordOptionsError} When options are invalid.
 */
export function createArgon2Driver(options: Argon2Options = {}): PasswordDriver {
  validateArgon2Options(options);

  const saltLength = options.saltLength ?? 16;

  /** Parameters passed to `needsRehash` - never include the (per-hash) salt. */
  const checkOptions: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: options.memoryCost ?? 2 ** 16,
    timeCost: options.timeCost ?? 3,
    parallelism: options.parallelism ?? 1,
    hashLength: options.hashLength ?? 32,
    version: options.version ?? 0x13,
  };

  return {
    /** Produces a salted Argon2id hash (PHC string format) with a fresh random salt per call. */
    async hash(password: string): Promise<string> {
      return argon2.hash(password, { ...checkOptions, salt: randomBytes(saltLength) });
    },

    /**
     * Returns `true` when the password matches; never throws on malformed
     * hashes. Stored hashes with parameters beyond the DoS caps are
     * rejected before the native library runs.
     */
    async verify(hash: string, password: string): Promise<boolean> {
      const params = parsePhcParams(hash);
      if (!params || exceedsCaps(params)) return false;
      try {
        return await argon2.verify(hash, password);
      } catch {
        return false;
      }
    },

    /**
     * Returns `true` when the hash uses parameters older than the current
     * config, or when its parameters exceed the DoS caps (flagged for
     * migration — such hashes cannot be verified safely).
     */
    async needsRehash(hash: string): Promise<boolean> {
      const params = parsePhcParams(hash);
      if (!params || exceedsCaps(params)) return true;
      try {
        return argon2.needsRehash(hash, checkOptions);
      } catch {
        return true;
      }
    },
  };
}