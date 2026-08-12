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
 * @module password/drivers/scrypt
 */

import { promisify } from "node:util";
import { randomBytes, timingSafeEqual, scrypt as scryptCallback } from "node:crypto";
import { PasswordOptionsError } from "../config";
import type { PasswordDriver, ScryptOptions } from "../types";

/** Default random salt length in bytes. */
const DEFAULT_SALT_LENGTH = 16;

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
 * key. Returns `null` for malformed or foreign hashes.
 *
 * @param hash - A stored hash string.
 * @returns The parsed components, or `null` when unrecognized.
 */
function parseHash(hash: string): ParsedScryptHash | null {
  const parts = hash.split("$").filter(Boolean);

  if (parts.length !== 6 || parts[0] !== "scrypt") return null;

  const cost = Number(parts[1].split("=")[1]);
  const blockSize = Number(parts[2].split("=")[1]);
  const parallelization = Number(parts[3].split("=")[1]);
  const salt = Buffer.from(parts[4], "base64url");
  const hashBuffer = Buffer.from(parts[5], "base64url");

  if (
    !Number.isFinite(cost) ||
    !Number.isFinite(blockSize) ||
    !Number.isFinite(parallelization) ||
    !salt.length ||
    !hashBuffer.length
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
  if (!Number.isInteger(blockSize) || blockSize < 1) {
    throw new PasswordOptionsError(`scrypt.blockSize must be an integer >= 1 (got ${blockSize}).`);
  }
  if (!Number.isInteger(parallelization) || parallelization < 1) {
    throw new PasswordOptionsError(
      `scrypt.parallelization must be an integer >= 1 (got ${parallelization}).`
    );
  }
  if (!Number.isInteger(keyLength) || keyLength < 1) {
    throw new PasswordOptionsError(`scrypt.keyLength must be an integer >= 1 (got ${keyLength}).`);
  }
  if (!Number.isInteger(saltLength) || saltLength < 8) {
    throw new PasswordOptionsError(`scrypt.saltLength must be an integer >= 8 (got ${saltLength}).`);
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