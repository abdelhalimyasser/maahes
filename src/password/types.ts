/**
 * @fileoverview Type definitions for the Maahes password module.
 *
 * This module implements password hashing, verification and policy
 * enforcement. It supports three algorithms out of the box (Argon2id,
 * bcrypt and scrypt), optional pepper-based secret mixing (HMAC-SHA256),
 * Unicode-aware policy validation and pluggable custom validation rules.
 *
 * @module password/types
 * @packageDocumentation
 */

/** Supported password hashing algorithms. */
export type PasswordAlgorithm = "argon2" | "bcrypt" | "scrypt";

/**
 * Writing systems allowed inside a password.
 * `"Any"` disables the script check entirely.
 */
export type PasswordScript = "Latin" | "Arabic" | "Cyrillic" | "Greek" | "Han" | "Any";

/**
 * Password normalization strategy applied before validation and hashing.
 * - `"none"`: the password is used exactly as provided.
 * - `"nfkc"`: the password is normalized with Unicode NFKC (recommended by
 *   OWASP to mitigate confusable-character and canonical-form bypasses).
 */
export type PasswordNormalization = "none" | "nfkc";

/**
 * Tuning options for the Argon2id driver (the default algorithm).
 *
 * @see https://github.com/ranisalt/node-argon2
 */
export interface Argon2Options {
  /** Memory cost in KiB. Must be at least `8 * parallelism`. Default `2 ** 16` (64 MiB). */
  memoryCost?: number;
  /** Number of iterations. Must be `>= 1`. Default `3`. */
  timeCost?: number;
  /** Number of parallel lanes. Must be `>= 1`. Default `1`. */
  parallelism?: number;
  /** Length of the derived key in bytes. Must be `>= 4`. Default `32`. */
  hashLength?: number;
  /** Length of the random salt in bytes. Must be `>= 8`. Default `16`. */
  saltLength?: number;
  /** Argon2 version tag: `0x10` (v1.0) or `0x13` (v1.3, default). */
  version?: 0x10 | 0x13;
}

/**
 * Tuning options for the bcrypt driver.
 *
 * Password input is truncated by bcrypt at 72 bytes; enabling `preHash`
 * removes that limitation by feeding bcrypt a SHA-256 digest instead.
 */
export interface BcryptOptions {
  /**
   * Number of hashing rounds (cost factor `2^saltRounds`).
   * Must be an integer between 4 and 31. Default 12.
   */
  saltRounds?: number;
  /**
   * When `true`, the password is pre-hashed with SHA-256 (hex) before
   * bcrypt is applied, eliminating the 72-byte truncation limit.
   * NOTE: hashes produced with `preHash` are NOT interchangeable with
   * standard (unprefixed) bcrypt hashes. Default `false`.
   */
  preHash?: boolean;
}

/**
 * Tuning options for the scrypt driver (implemented on `node:crypto`).
 */
export interface ScryptOptions {
  /**
   * CPU/memory cost parameter `N`. Must be a power of two `>= 2`.
   * Default `2 ** 14` (16384).
   */
  cost?: number;
  /** Block size parameter `r`. Must be `>= 1`. Default `8`. */
  blockSize?: number;
  /** Parallelization parameter `p`. Must be `>= 1`. Default `1`. */
  parallelization?: number;
  /** Length of the derived key in bytes. Must be `>= 1`. Default `64`. */
  keyLength?: number;
  /** Length of the random salt in bytes. Must be `>= 8`. Default `16`. */
  saltLength?: number;
  /**
   * Maximum memory (in bytes) scrypt may use.
   * Default `128 * cost * blockSize * 2`, which matches Node's internal budget.
   */
  maxmem?: number;
}

/**
 * A user-defined validation rule evaluated by the policy engine.
 *
 * The `test` callback returns `true` when the password SATISFIES the rule;
 * a `false` result records a violation keyed by `rule`.
 */
export interface CustomPasswordRule {
  /** Stable identifier reported in `PolicyViolation.rule`. */
  rule: string;
  /** Optional human-readable message; a default one is generated when omitted. */
  message?: string;
  /**
   * Predicate evaluated against the candidate password and the fully
   * resolved (defaults-merged) policy. Return `true` to mark the rule as
   * satisfied, `false` to raise a violation.
   */
  test: (password: string, policy: Required<PasswordPolicyOptions>) => boolean;
}

/**
 * Constraints applied to passwords before they are hashed (or on demand
 * via {@link PasswordModule.validatePassword}).
 */
export interface PasswordPolicyOptions {
  /** Minimum password length in Unicode code points. Default `8`. */
  minLength?: number;
  /** Maximum password length in Unicode code points. Default `128`. */
  maxLength?: number;
  /** Minimum required uppercase letters. Default `0` (disabled). */
  minUppercase?: number;
  /** Minimum required lowercase letters. Default `0` (disabled). */
  minLowercase?: number;
  /** Minimum required ASCII digits. Default `0` (disabled). */
  minDigits?: number;
  /** Minimum required symbol characters. Default `0` (disabled). */
  minSymbols?: number;
  /**
   * Minimum estimated entropy in bits (see {@link estimateEntropy}).
   * Default `0` (disabled).
   */
  minEntropy?: number;
  /**
   * Writing scripts permitted in the password. A letter from any other
   * script fails the check. `"Any"` disables the check.
   * Default `["Latin"]`.
   */
  allowedScripts?: PasswordScript[];
  /** Reject passwords containing whitespace. Default `true`. */
  blockWhitespace?: boolean;
  /**
   * Exact-match blocklist (e.g. common passwords), compared
   * case-insensitively. Default `[]`.
   */
  blockedPasswords?: string[];
  /** User-defined rules evaluated after the built-in ones. Default `[]`. */
  customRules?: CustomPasswordRule[];
  /**
   * When `true`, `hashPassword()` and `pepperedHashPassword()` throw a
   * {@link PasswordPolicyError} for passwords that violate the policy.
   * Default `false`.
   */
  enforceOnHash?: boolean;
}

/** A single rule violation produced by {@link validatePassword}. */
export interface PolicyViolation {
  /** Identifier of the violated rule, e.g. `"minLength"` or a custom rule name. */
  rule: string;
  /** Human-readable explanation of the violation. */
  message: string;
}

/** Result of a policy check. */
export interface PolicyResult {
  /** `true` when the password satisfies every rule. */
  valid: boolean;
  /** Every unsatisfied rule; empty when `valid` is `true`. */
  violations: PolicyViolation[];
}

/**
 * Configuration accepted by the {@link Password} factory. Every field is
 * optional; omitted values fall back to {@link DEFAULT_PASSWORD_CONFIG}.
 */
export interface PasswordConfig {
  /** Hashing algorithm. Default `"argon2"`. */
  algorithm?: PasswordAlgorithm;
  /**
   * Site-wide secret mixed into every hash via HMAC-SHA256 (peppering).
   * Falls back to the `PASSWORD_PEPPER` environment variable when unset.
   */
  pepper?: string;
  /** Password normalization strategy. Default `"none"`. */
  normalize?: PasswordNormalization;
  /** Argon2id driver options. */
  argon2?: Argon2Options;
  /** bcrypt driver options. */
  bcrypt?: BcryptOptions;
  /** scrypt driver options. */
  scrypt?: ScryptOptions;
  /** Policy constraints. */
  policy?: PasswordPolicyOptions;
}

/**
 * Internal contract implemented by every hashing driver.
 * All methods must never throw on malformed input; `verify` and
 * `needsRehash` report failure gracefully instead.
 */
export interface PasswordDriver {
  /** Produces a salted password hash (encodes parameters and salt). */
  hash(password: string): Promise<string>;
  /** Returns `true` when `password` matches `hash`; never throws. */
  verify(hash: string, password: string): Promise<boolean>;
  /** Returns `true` when `hash` was produced with outdated parameters. */
  needsRehash(hash: string): Promise<boolean>;
}

/** Result of {@link PasswordModule.verifyAndRehash}. */
export interface VerifyResult {
  /** `true` when the password matched the stored hash. */
  valid: boolean;
  /**
   * A freshly hashed replacement for the stored hash when the stored one
   * used outdated parameters; `undefined` otherwise.
   */
  newHash?: string;
}

/**
 * The public API of the password module, created by the {@link Password}
 * factory. Every instance is immutable and safe to share across requests.
 */
export interface PasswordModule {
  /** Hashes `password` with the configured algorithm; subject to policy when `enforceOnHash` is enabled. */
  hashPassword(password: string): Promise<string>;
  /**
   * Re-hashes an already-accepted password (e.g. during login upgrades).
   * Never subject to policy validation, even with `enforceOnHash` enabled.
   */
  rehashPassword(password: string): Promise<string>;
  /**
   * Verifies `password` against `hash`. When the hash carries the pepper
   * marker, the configured pepper is applied automatically. Never throws
   * on malformed hash formats (returns `false`).
   */
  verifyPassword(hash: string, password: string): Promise<boolean>;
  /** Returns `true` when `hash` should be regenerated with current parameters. */
  needsRehash(hash: string): Promise<boolean>;
  /** Hashes `password` with pepper applied and wraps it in the pepper marker. */
  pepperedHashPassword(password: string): Promise<string>;
  /**
   * Verifies a peppered hash. Accepts both marked hashes (marker
   * transparently handled) and legacy unmarked HMAC-peppered hashes.
   */
  pepperedVerifyPassword(hash: string, password: string): Promise<boolean>;
  /**
   * One-shot login helper: verifies `password` and, when the stored hash
   * is outdated, returns a fresh hash for immediate persistence.
   */
  verifyAndRehash(hash: string, password: string): Promise<VerifyResult>;
  /** Checks `password` against the configured policy WITHOUT hashing it. */
  validatePassword(password: string): PolicyResult;
}