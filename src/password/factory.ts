/**
 * @fileoverview The `Password()` factory: assembles the public module API
 * from resolved config, a selected algorithm driver and the policy engine.
 *
 * Responsibilities:
 * - select and construct the algorithm driver (fails fast on bad options),
 * - normalize input (optional NFKC) before any policy check or hashing,
 * - enforce `enforceOnHash` policy gating on hash paths,
 * - apply HMAC-SHA256 peppering and the pepper marker,
 * - expose the combined {@link PasswordModule} surface.
 *
 * @module password/factory
 */

import { createHmac } from "node:crypto";
import { DEFAULT_PASSWORD_CONFIG, mergeConfig, parseConfigInput } from "./config";
import { pepperId, stripPepperMarker, isPepperedHash, wrapPepperMarker } from "./detect";
import { createArgon2Driver } from "./drivers/argon2";
import { createBcryptDriver } from "./drivers/bcrypt";
import { createScryptDriver } from "./drivers/scrypt";
import { validatePassword, PasswordPolicyError } from "./policy";
import type {
  PasswordAlgorithm,
  PasswordConfig,
  PasswordDriver,
  PasswordModule,
  PasswordPolicyOptions,
  VerifyResult,
} from "./types";

/**
 * Selects and constructs the driver for the configured algorithm.
 *
 * @param config - Fully-resolved module configuration.
 * @returns The matching {@link PasswordDriver}.
 * @throws {Error} For unknown algorithms; {@link PasswordOptionsError} for invalid options.
 */
function selectDriver(config: PasswordConfig): PasswordDriver {
  const algorithm: PasswordAlgorithm = config.algorithm ?? DEFAULT_PASSWORD_CONFIG.algorithm;
  switch (algorithm) {
    case "argon2":
      return createArgon2Driver(config.argon2);
    case "bcrypt":
      return createBcryptDriver(config.bcrypt);
    case "scrypt":
      return createScryptDriver(config.scrypt);
    default:
      throw new Error(`Unknown password algorithm: "${algorithm}".`);
  }
}

/**
 * HMAC-SHA256-peppers a password with a site secret. The digest is
 * hex-encoded before hashing, so any driver can consume it as a string.
 *
 * @param password - The raw password to pepper.
 * @param pepper - The site pepper secret.
 * @returns The peppered (HMAC) password.
 * @throws {Error} When no pepper is configured - peppered operations must
 *   never silently fall back to unpeppered behavior.
 */
function applyPepper(password: string, pepper?: string): string {
  if (!pepper) {
    throw new Error(
      "Peppered password operations require a pepper. Set config.pepper or the PASSWORD_PEPPER environment variable."
    );
  }
  return createHmac("sha256", pepper).update(password, "utf8").digest("hex");
}

/**
 * Creates an immutable password module instance.
 *
 * Overloads (see `Password`):
 * - no argument:      defaults
 * - config object:    partial config, deep-merged over defaults
 * - JSON string:      inline config JSON (`{"password": {...}}` unwrapped)
 * - file path string: read and parsed as JSON
 *
 * @param input - Partial configuration, inline JSON, or a path to a JSON file.
 * @returns A {@link PasswordModule} bound to the resolved configuration.
 * @throws {Error} For unknown algorithms or malformed config input;
 *   {@link PasswordOptionsError} for out-of-range algorithm options.
 */
export function Password(input?: PasswordConfig | string): PasswordModule {
  const userConfig = parseConfigInput(input);
  const config = mergeConfig(userConfig);
  const driver = selectDriver(config);
  const policy = config.policy as Required<PasswordPolicyOptions>;

  /** Applies the configured normalization strategy to a raw password. */
  const normalize = (password: string): string =>
    config.normalize === "nfkc" ? password.normalize("NFKC") : password;

  /**
   * Throws on policy violations when `enforceOnHash` is enabled.
   * @throws {PasswordPolicyError} On violation with enforcement enabled.
   */
  function assertPolicyOrThrow(password: string): void {
    if (!policy.enforceOnHash) return;
    const result = validatePassword(password, policy);
    if (!result.valid) throw new PasswordPolicyError(result.violations);
  }

  return {
    /** Hashes a password with the configured algorithm (policy-gated when `enforceOnHash`). */
    async hashPassword(password: string): Promise<string> {
      const normalized = normalize(password);
      assertPolicyOrThrow(normalized);
      return driver.hash(normalized);
    },

    /**
     * Re-hashes an already-accepted password (login-time upgrades).
     * Deliberately SKIPS policy validation, mirroring `rehashPassword`'s
     * contract (see {@link PasswordModule.rehashPassword}).
     */
    async rehashPassword(password: string): Promise<string> {
      return driver.hash(normalize(password));
    },

    /**
     * Verifies a password; pepper-marked hashes are unwrapped and the
     * configured pepper is applied automatically. Never throws on
     * malformed hashes (returns `false`).
     */
    async verifyPassword(hash: string, password: string): Promise<boolean> {
      const normalized = normalize(password);
      if (isPepperedHash(hash)) {
        return driver.verify(stripPepperMarker(hash), applyPepper(normalized, config.pepper));
      }
      return driver.verify(hash, normalized);
    },

    /** Flags hashes produced with outdated parameters; pepper markers are handled transparently. */
    async needsRehash(hash: string): Promise<boolean> {
      const inner = isPepperedHash(hash) ? stripPepperMarker(hash) : hash;
      return driver.needsRehash(inner);
    },

    /** Hashes a password with pepper applied, wrapped in the pepper marker. */
    async pepperedHashPassword(password: string): Promise<string> {
      const normalized = normalize(password);
      assertPolicyOrThrow(normalized);
      return wrapPepperMarker(config.pepper as string, await driver.hash(applyPepper(normalized, config.pepper)));
    },

    /**
     * Verifies a peppered password against a hash. Accepts both
     * pepper-marked hashes (marker handled transparently) and legacy
     * unmarked HMAC-peppered hashes (migration path).
     */
    async pepperedVerifyPassword(hash: string, password: string): Promise<boolean> {
      const inner = isPepperedHash(hash) ? stripPepperMarker(hash) : hash;
      return driver.verify(inner, applyPepper(normalize(password), config.pepper));
    },

    /**
     * One-shot login flow: verifies, then rehashes when the stored hash
     * uses outdated parameters. The returned `newHash` preserves the
     * pepper-marked (or plain) storage format of the input hash.
     */
    async verifyAndRehash(hash: string, password: string): Promise<VerifyResult> {
      const marked = isPepperedHash(hash);
      const inner = marked ? stripPepperMarker(hash) : hash;
      const normalized = normalize(password);
      const candidate = marked ? applyPepper(normalized, config.pepper) : normalized;

      const valid = await driver.verify(inner, candidate);
      if (!valid) return { valid: false };

      if (!(await driver.needsRehash(inner))) {
        return { valid: true };
      }

      const newHash = await driver.hash(candidate);
      return { valid: true, newHash: marked ? wrapPepperMarker(config.pepper as string, newHash) : newHash };
    },

    /** Checks a password against the configured policy without hashing. */
    validatePassword(password: string) {
      return validatePassword(normalize(password), policy);
    },
  };
}

/** Re-export the canonical defaults for tooling and introspection. */
export { DEFAULT_PASSWORD_CONFIG, PasswordOptionsError } from "./config";

/** Re-export the policy error type alongside the module surface. */
export { PasswordPolicyError } from "./policy";