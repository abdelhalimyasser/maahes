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
 * @module password/drivers/argon2
 */

import * as argon2 from "argon2";
import { randomBytes } from "node:crypto";
import { PasswordOptionsError } from "../config";
import type { Argon2Options, PasswordDriver } from "../types";

/**
 * Validates Argon2 options against the algorithm's hard constraints.
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
  if (!Number.isInteger(memoryCost) || memoryCost < 8 * parallelism) {
    throw new PasswordOptionsError(
      `argon2.memoryCost must be an integer >= 8 * parallelism (${8 * parallelism}) (got ${memoryCost}).`
    );
  }
  if (!Number.isInteger(timeCost) || timeCost < 1) {
    throw new PasswordOptionsError(`argon2.timeCost must be an integer >= 1 (got ${timeCost}).`);
  }
  if (!Number.isInteger(hashLength) || hashLength < 4) {
    throw new PasswordOptionsError(`argon2.hashLength must be an integer >= 4 (got ${hashLength}).`);
  }
  if (!Number.isInteger(saltLength) || saltLength < 8) {
    throw new PasswordOptionsError(`argon2.saltLength must be an integer >= 8 (got ${saltLength}).`);
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

    /** Returns `true` when the password matches; never throws on malformed hashes. */
    async verify(hash: string, password: string): Promise<boolean> {
      try {
        return await argon2.verify(hash, password);
      } catch {
        return false;
      }
    },

    /** Returns `true` when the hash uses parameters older than the current config. */
    async needsRehash(hash: string): Promise<boolean> {
      try {
        return argon2.needsRehash(hash, checkOptions);
      } catch {
        return true;
      }
    },
  };
}