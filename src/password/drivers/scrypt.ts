/**
 * @fileoverview scrypt driver.
 *
 * scrypt (RFC 7914) is a memory-hard KDF implemented natively by
 * `node:crypto`, so this driver has zero native dependencies beyond the
 * runtime. It writes a self-describing hash format that embeds its own
 * parameters (N, r, p) so verification and rehash detection work even
 * after configuration changes:
 *
 * `$scrypt$N=<cost>$r=<blockSize>$p=<parallelization>$<salt>$<hash>`
 *
 * Verification uses `timingSafeEqual` to avoid timing side channels.
 *
 * DoS guard: construction-time caps bound how expensive a configuration
 * may be, and parsing rejects stored hashes with oversized sections or
 * parameters beyond those caps BEFORE any KDF work or buffer allocation
 * happens — a crafted hash with absurd embedded N would otherwise make
 * every login attempt allocate gigabytes. Over-cap hashes fail
 * verification and are flagged for migration by `needsRehash`.
 *
 * @module password/drivers/scrypt
 */

import { promisify } from "node:util";
import { randomBytes, timingSafeEqual, scrypt as scryptCallback } from "node:crypto";
import { PasswordOptionsError } from "../config";
import type { PasswordDriver, ScryptOptions } from "../types";

/** Default random salt length in bytes. */
const DEFAULT_SALT_LENGTH = 16;
/** Upper bound for `cost` (N) — 16× the 2^14 default. */
export const SCRYPT_MAX_COST = 2 ** 18;
/** Upper bound for `blockSize` (r). */
export const SCRYPT_MAX_BLOCK_SIZE = 16;
/** Upper bound for `parallelization` (p). */
export const SCRYPT_MAX_PARALLELIZATION = 8;
/** Upper bound for `keyLength` (bytes). */
export const SCRYPT_MAX_KEY_LENGTH = 128;
/** Upper bound for the stored salt section (base64url chars). */
const MAX_SALT_SECTION = 128;
/** Upper bound for the stored derived-key section (base64url chars). */
const MAX_HASH_SECTION = 256;
/** Total string length guard applied before any parsing. */
const MAX_HASH_LENGTH = 2048;

/** Promisified `node:crypto` scrypt with an explicit option shape. */
const scryptAsync = promisify(scryptCallback) as unknown as (
  password: string,
  salt: Buffer,
  keyLength: number,
  options: { N: number; r: number; p: number; maxmem: number }
) => Promise<Buffer>;

/** Parsed representation of a stored scrypt hash. */
interface ParsedScryptHash {
  /** CPU/memory cost parameter N. */
  cost: number;
  /** Block size parameter r. */
  blockSize: number;
  /** Parallelization parameter p. */
  parallelization: number;
  /** Random salt. */
  salt: Buffer;
  /** Derived key bytes. */
  hash: Buffer;
}

/**
 * The memory scrypt may use for parameter set (N, r): `128 * N * r` bytes
 * of scratch workspace plus operating buffer space; doubled for safety, in
 * line with Node's default budget.
 *
 * @param cost - scrypt cost parameter N.
 * @param blockSize - scrypt block size r.
 * @returns Recommended `maxmem` in bytes.
 */
function maxmemFor(cost: number, blockSize: number): number {
  return 128 * cost * blockSize * 2;
}

/**
 * Encodes a scrypt hash in the self-describing format with base64url salt
 * and derived key.
 *
 * @param params - Derivation parameters embedded for future verification.
 * @param salt - Random salt bytes.
 * @param derived - Derived key bytes.
 * @returns The full `$scrypt$...` hash string.
 */
function encodeHash(
  params: { cost: number; blockSize: number; parallelization: number },
  salt: Buffer,
  derived: Buffer
): string {
  return `$scrypt$N=${params.cost}$r=${params.blockSize}$p=${params.parallelization}$${salt.toString(
    "base64url"
  )}$${derived.toString("base64url")}`;
}

/**
 * Parses a stored scrypt hash back into its parameters, salt and derived
 * key. Returns `null` for malformed or foreign hashes. Parsing is
 * bounded: oversized strings, sections or parameters beyond the driver's
 * DoS caps are rejected without allocating or deriving anything.
 *
 * @param hash - A stored hash string.
 * @returns The parsed components, or `null` when unrecognized or over-cap.
 */
function parseHash(hash: string): ParsedScryptHash | null {
  if (hash.length > MAX_HASH_LENGTH) return null;
  const parts = hash.split("$").filter(Boolean);

  if (parts.length !== 6 || parts[0] !== "scrypt") return null;

  const cost = Number(parts[1].split("=")[1]);
  const blockSize = Number(parts[2].split("=")[1]);
  const parallelization = Number(parts[3].split("=")[1]);

  if (
    !Number.isFinite(cost) ||
    !Number.isFinite(blockSize) ||
    !Number.isFinite(parallelization) ||
    cost > SCRYPT_MAX_COST ||
    blockSize > SCRYPT_MAX_BLOCK_SIZE ||
    parallelization > SCRYPT_MAX_PARALLELIZATION ||
    parts[4].length > MAX_SALT_SECTION ||
    parts[5].length > MAX_HASH_SECTION
  ) {
    return null;
  }

  const salt = Buffer.from(parts[4], "base64url");
  const hashBuffer = Buffer.from(parts[5], "base64url");

  if (
    !salt.length ||
    !hashBuffer.length ||
    salt.length > 96 ||
    hashBuffer.length > SCRYPT_MAX_KEY_LENGTH
  ) {
    return null;
  }

  return { cost, blockSize, parallelization, salt, hash: hashBuffer };
}

/**
 * Validates scrypt options against `node:crypto` constraints.
 *
 * @param options - Driver options (defaults applied for missing fields).
 * @throws {PasswordOptionsError} When any option is out of range.
 */
export function validateScryptOptions(options: ScryptOptions): void {
  const cost = options.cost ?? 2 ** 14;
  const blockSize = options.blockSize ?? 8;
  const parallelization = options.parallelization ?? 1;
  const keyLength = options.keyLength ?? 64;
  const saltLength = options.saltLength ?? DEFAULT_SALT_LENGTH;

  if (!Number.isInteger(cost) || cost < 2 || (cost & (cost - 1)) !== 0) {
    throw new PasswordOptionsError(`scrypt.cost must be a power of two >= 2 (got ${cost}).`);
  }
  if (cost > SCRYPT_MAX_COST) {
    throw new PasswordOptionsError(
      `scrypt.cost must be <= ${SCRYPT_MAX_COST} (DoS guard, got ${cost}).`
    );
  }
  if (!Number.isInteger(blockSize) || blockSize < 1) {
    throw new PasswordOptionsError(`scrypt.blockSize must be an integer >= 1 (got ${blockSize}).`);
  }
  if (blockSize > SCRYPT_MAX_BLOCK_SIZE) {
    throw new PasswordOptionsError(
      `scrypt.blockSize must be <= ${SCRYPT_MAX_BLOCK_SIZE} (DoS guard, got ${blockSize}).`
    );
  }
  if (!Number.isInteger(parallelization) || parallelization < 1) {
    throw new PasswordOptionsError(
      `scrypt.parallelization must be an integer >= 1 (got ${parallelization}).`
    );
  }
  if (parallelization > SCRYPT_MAX_PARALLELIZATION) {
    throw new PasswordOptionsError(
      `scrypt.parallelization must be <= ${SCRYPT_MAX_PARALLELIZATION} (DoS guard, got ${parallelization}).`
    );
  }
  if (!Number.isInteger(keyLength) || keyLength < 1) {
    throw new PasswordOptionsError(`scrypt.keyLength must be an integer >= 1 (got ${keyLength}).`);
  }
  if (keyLength > SCRYPT_MAX_KEY_LENGTH) {
    throw new PasswordOptionsError(
      `scrypt.keyLength must be <= ${SCRYPT_MAX_KEY_LENGTH} (DoS guard, got ${keyLength}).`
    );
  }
  if (!Number.isInteger(saltLength) || saltLength < 8) {
    throw new PasswordOptionsError(`scrypt.saltLength must be an integer >= 8 (got ${saltLength}).`);
  }
  if (saltLength > 96) {
    throw new PasswordOptionsError(`scrypt.saltLength must be <= 96 (DoS guard, got ${saltLength}).`);
  }
  if (
    options.maxmem !== undefined &&
    (!Number.isFinite(options.maxmem) || options.maxmem < maxmemFor(cost, blockSize))
  ) {
    throw new PasswordOptionsError(
      `scrypt.maxmem must be >= ${maxmemFor(cost, blockSize)} bytes for the given cost/blockSize (got ${options.maxmem}).`
    );
  }
}

/**
 * Creates a scrypt password driver built on `node:crypto`.
 *
 * @param options - scrypt tuning options; missing fields fall back to the
 *   documented defaults.
 * @returns A {@link PasswordDriver} implementation.
 * @throws {PasswordOptionsError} When options are invalid.
 */
export function createScryptDriver(options: ScryptOptions = {}): PasswordDriver {
  validateScryptOptions(options);

  const cost = options.cost ?? 2 ** 14;
  const blockSize = options.blockSize ?? 8;
  const parallelization = options.parallelization ?? 1;
  const keyLength = options.keyLength ?? 64;
  const saltLength = options.saltLength ?? DEFAULT_SALT_LENGTH;

  return {
    /** Produces a salted scrypt hash in the self-describing `$scrypt$` format. */
    async hash(password: string): Promise<string> {
      const salt = randomBytes(saltLength);

      const derived = await scryptAsync(password, salt, keyLength, {
        N: cost,
        r: blockSize,
        p: parallelization,
        maxmem: options.maxmem ?? maxmemFor(cost, blockSize),
      });

      return encodeHash({ cost, blockSize, parallelization }, salt, derived);
    },

    /** Returns `true` when the password matches via constant-time comparison; never throws. */
    async verify(hash: string, password: string): Promise<boolean> {
      try {
        const parsed = parseHash(hash);
        if (!parsed) return false;

        const derived = await scryptAsync(password, parsed.salt, parsed.hash.length, {
          N: parsed.cost,
          r: parsed.blockSize,
          p: parsed.parallelization,
          maxmem: maxmemFor(parsed.cost, parsed.blockSize),
        });

        if (derived.length !== parsed.hash.length) return false;
        return timingSafeEqual(derived, parsed.hash);
      } catch {
        return false;
      }
    },

    /** Returns `true` when any derivation parameter differs from the current config. */
    async needsRehash(hash: string): Promise<boolean> {
      const parsed = parseHash(hash);
      if (!parsed) return true;

      return (
        parsed.cost !== cost ||
        parsed.blockSize !== blockSize ||
        parsed.parallelization !== parallelization ||
        parsed.hash.length !== keyLength
      );
    },
  };
}