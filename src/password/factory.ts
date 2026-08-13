/**
 * @fileoverview The `Password()` factory: assembles the public module API
 * from resolved config, algorithm drivers and the policy engine.
 *
 * Responsibilities:
 * - validate configuration up front (every driver's option set, the
 *   pepper keyring and the policy), failing fast on invalid input,
 * - select and construct the configured algorithm driver plus lazily
 *   created drivers for the other algorithms (used for automatic
 *   detection-based verification of legacy hashes),
 * - normalize input (optional NFKC) before any policy check or hashing,
 * - enforce `enforceOnHash` policy gating on hash paths,
 * - apply HMAC-SHA256 peppering via the pepper keyring, selecting the
 *   exact secret that produced a marked hash by its id,
 * - expose the combined {@link PasswordModule} surface.
 *
 * @module password/factory
 */

import { createHmac } from "node:crypto";
import {
  DEFAULT_PASSWORD_CONFIG,
  mergeConfig,
  parseConfigInput,
  resolvePepper,
  type PepperRing,
} from "./config";
import {
  detectHashAlgorithm,
  extractPepperId,
  isPepperedHash,
  stripPepperMarker,
  wrapPepperMarker,
} from "./detect";
import { createArgon2Driver, validateArgon2Options } from "./drivers/argon2";
import { createBcryptDriver, validateBcryptOptions } from "./drivers/bcrypt";
import { createScryptDriver, validateScryptOptions } from "./drivers/scrypt";
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
 * Selects and constructs the driver for an algorithm.
 *
 * @param config - Fully-resolved module configuration.
 * @param algorithm - The algorithm to construct a driver for.
 * @returns The matching {@link PasswordDriver}.
 * @throws {Error} For unknown algorithms; {@link PasswordOptionsError} for invalid options.
 */
function selectDriver(config: PasswordConfig, algorithm: PasswordAlgorithm): PasswordDriver {
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
 * @param secret - The pepper secret selected for this hash.
 * @returns The peppered (HMAC) password.
 */
function applyPepper(password: string, secret: string): string {
  return createHmac("sha256", secret).update(password, "utf8").digest("hex");
}

/** Error message used when a peppered operation has no pepper configured. */
const NO_PEPPER_MESSAGE =
  "Peppered password operations require a pepper. Set config.pepper or the PASSWORD_PEPPER environment variable.";

/**
 * Looks up the secret for a pepper id in the keyring (current first,
 * then previous, in order).
 *
 * @param ring - The resolved pepper keyring.
 * @param id - The pepper id embedded in a marked hash.
 * @returns The matching secret, or `undefined` for unknown ids (fail-safe).
 */
function findPepperSecret(ring: PepperRing, id: string): string | undefined {
  if (ring.current.id === id) return ring.current.secret;
  for (const key of ring.previous) {
    if (key.id === id) return key.secret;
  }
  return undefined;
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
 *   {@link PasswordOptionsError} for out-of-range algorithm options or
 *   an invalid pepper keyring.
 */
export function Password(input?: PasswordConfig | string): PasswordModule {
  const userConfig = parseConfigInput(input);
  const config = mergeConfig(userConfig);

  // Every driver option set is validated at construction — an invalid
  // bcrypt config is a bug even when the module hashes with argon2, and
  // must never surface mid-request through automatic detection.
  validateArgon2Options(config.argon2 ?? {});
  validateBcryptOptions(config.bcrypt ?? {});
  validateScryptOptions(config.scrypt ?? {});

  const algorithm: PasswordAlgorithm = config.algorithm ?? DEFAULT_PASSWORD_CONFIG.algorithm;
  const ring: PepperRing | undefined = resolvePepper(
    userConfig.pepper,
    process.env.PASSWORD_PEPPER
  );
  const policy = config.policy as Required<PasswordPolicyOptions>;

  const driver = selectDriver(config, algorithm);
  const drivers = new Map<PasswordAlgorithm, PasswordDriver>([[algorithm, driver]]);

  /** Returns a driver for any supported algorithm (created lazily). */
  const driverFor = (algo: PasswordAlgorithm): PasswordDriver => {
    let existing = drivers.get(algo);
    if (!existing) {
      existing = selectDriver(config, algo);
      drivers.set(algo, existing);
    }
    return existing;
  };

  /**
   * Selects the driver that must verify a stored hash: the driver of the
   * hash's own detected algorithm (embedded parameters make verification
   * self-contained), falling back to the configured driver for
   * unrecognized formats (which verify as `false`).
   */
  const verificationDriverFor = (hash: string): PasswordDriver =>
    driverFor(detectHashAlgorithm(hash) ?? algorithm);

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

  /**
   * Shared marked-hash verification: selects the exact secret from the
   * keyring by the marker's id and verifies with the hash's own
   * algorithm driver. Unknown ids and corrupted markers fail safely.
   */
  const verifyMarked = (hash: string, normalized: string): Promise<boolean> => {
    if (!ring) return Promise.resolve(false);
    const id = extractPepperId(hash);
    if (id === null) return Promise.resolve(false);
    const secret = findPepperSecret(ring, id);
    if (secret === undefined) return Promise.resolve(false);
    return verificationDriverFor(hash).verify(stripPepperMarker(hash), applyPepper(normalized, secret));
  };

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
     * Verifies a password. Pepper-marked hashes are unwrapped and the
     * exact secret that produced them is selected from the keyring by
     * the marker's id; unknown ids fail safely (`false`). The hash's own
     * algorithm is detected automatically, so legacy hashes from any
     * supported algorithm verify without application changes. Never
     * throws on malformed hashes (returns `false`).
     */
    async verifyPassword(hash: string, password: string): Promise<boolean> {
      const normalized = normalize(password);
      if (isPepperedHash(hash)) {
        return verifyMarked(hash, normalized);
      }
      return verificationDriverFor(hash).verify(hash, normalized);
    },

    /**
     * Flags hashes produced with outdated parameters or a stale
     * algorithm/pepper. Unknown formats, malformed hashes and hashes
     * whose parameters exceed the verification DoS caps are flagged for
     * migration. Pepper markers are handled transparently.
     */
    async needsRehash(hash: string): Promise<boolean> {
      const marked = isPepperedHash(hash);
      const inner = marked ? stripPepperMarker(hash) : hash;
      const detected = detectHashAlgorithm(inner);

      if (detected === null) return true;
      if (marked && ring !== undefined && extractPepperId(hash) !== ring.current.id) return true;
      if (marked && ring === undefined) return true;
      if (detected !== algorithm) return true;
      return driver.needsRehash(inner);
    },

    /** Hashes a password with the current pepper applied, wrapped in the pepper marker. */
    async pepperedHashPassword(password: string): Promise<string> {
      const normalized = normalize(password);
      assertPolicyOrThrow(normalized);
      if (!ring) throw new Error(NO_PEPPER_MESSAGE);
      return wrapPepperMarker(
        ring.current.id,
        await driver.hash(applyPepper(normalized, ring.current.secret))
      );
    },

    /**
     * Verifies a peppered password against a hash.
     *
     * - Marked hashes: the exact secret is selected from the keyring by
     *   the marker's id (unknown ids fail safely).
     * - Legacy unmarked hashes (pre-marker era): tried against the
     *   current secret first, then each previous secret in order. This
     *   costs one KDF per secret and only applies to the legacy format.
     */
    async pepperedVerifyPassword(hash: string, password: string): Promise<boolean> {
      if (isPepperedHash(hash)) {
        return verifyMarked(hash, normalize(password));
      }
      if (!ring) throw new Error(NO_PEPPER_MESSAGE);
      const normalized = normalize(password);
      const innerDriver = verificationDriverFor(hash);
      const candidates = [ring.current.secret, ...ring.previous.map((key) => key.secret)];
      for (const secret of candidates) {
        if (await innerDriver.verify(hash, applyPepper(normalized, secret))) {
          return true;
        }
      }
      return false;
    },

    /**
     * One-shot login flow: verifies, then rehashes when the stored hash
     * is outdated. A replacement hash is produced when any of these
     * holds:
     *
     * - the hash's algorithm differs from the configured one (migration),
     * - the hash's driver parameters differ from the configured ones,
     * - the hash is pepper-marked with an id other than the current one
     *   (pepper rotation — the replacement always uses the current secret),
     * - the hash format is unrecognized (it can never verify, so this
     *   path is unreachable in practice).
     *
     * A replacement hash is NEVER produced when verification failed.
     * The returned `newHash` preserves the pepper-marked (or plain)
     * storage format of the input hash.
     */
    async verifyAndRehash(hash: string, password: string): Promise<VerifyResult> {
      const marked = isPepperedHash(hash);
      const inner = marked ? stripPepperMarker(hash) : hash;
      const normalized = normalize(password);

      let pepperSecret: string | undefined;
      if (marked) {
        if (!ring) return { valid: false };
        const id = extractPepperId(hash);
        if (id === null) return { valid: false };
        pepperSecret = findPepperSecret(ring, id);
        if (pepperSecret === undefined) return { valid: false };
      }

      const detected = detectHashAlgorithm(inner);
      const candidate = marked ? applyPepper(normalized, pepperSecret as string) : normalized;
      const verificationDriver = detected ? driverFor(detected) : driver;

      const valid = await verificationDriver.verify(inner, candidate);
      if (!valid) return { valid: false };

      const rehashNeeded =
        detected === null ||
        detected !== algorithm ||
        (marked && extractPepperId(hash) !== ring?.current.id) ||
        (await verificationDriver.needsRehash(inner));

      if (!rehashNeeded) return { valid: true };

      const newHash = await driver.hash(candidate);
      return {
        valid: true,
        newHash: marked ? wrapPepperMarker(ring?.current.id as string, newHash) : newHash,
      };
    },

    /** Checks a password against the configured policy without hashing. */
    validatePassword(password: string) {
      return validatePassword(normalize(password), policy);
    },
  };
}

/** Re-export the canonical defaults for tooling and introspection. */
export { DEFAULT_PASSWORD_CONFIG, PasswordOptionsError, resolvePepper } from "./config";

/** Re-export the policy error type alongside the module surface. */
export { PasswordPolicyError } from "./policy";