/**
 * @fileoverview Defaults, parsing and merging of password module config.
 *
 * `Password` accepts configuration as a plain object, a JSON string or a
 * path to a JSON file. Every omitted field falls back to
 * {@link DEFAULT_PASSWORD_CONFIG} via a deep merge, so partial
 * configuration (e.g. only `{ algorithm: "bcrypt" }`) behaves intuitively.
 *
 * @module password/config
 */

import { readFileSync } from "node:fs";
import { deepMerge } from "../shared/deepMerge";
import { MaahesOptionsError } from "../shared/errors";
import { isValidPepperId, pepperId } from "./detect";
import type { PasswordConfig, PepperConfig, PepperKey } from "./types";

/**
 * The canonical, fully-populated default configuration of the password
 * module. This is the single source of truth for every default value;
 * drivers and policy components never re-declare defaults of their own
 * (beyond defensive fallbacks), so option handling cannot drift.
 */
export const DEFAULT_PASSWORD_CONFIG: Required<Omit<PasswordConfig, "pepper">> & {
  /** Peppering config; intentionally optional and resolved from the environment as a fallback. */
  pepper?: PepperConfig;
} = {
  algorithm: "argon2",
  normalize: "none",
  argon2: {
    memoryCost: 2 ** 16, // 64 MiB
    timeCost: 3,
    parallelism: 1,
    hashLength: 32,
    saltLength: 16,
    version: 0x13,
  },
  bcrypt: {
    saltRounds: 12,
    preHash: false,
  },
  scrypt: {
    cost: 2 ** 14,
    blockSize: 8,
    parallelization: 1,
    keyLength: 64,
    saltLength: 16,
  },
  policy: {
    minLength: 8,
    maxLength: 128,
    minUppercase: 0,
    minLowercase: 0,
    minDigits: 0,
    minSymbols: 0,
    minEntropy: 0,
    allowedScripts: ["Any"],
    blockWhitespace: true,
    blockedPasswords: [],
    customRules: [],
    enforceOnHash: false,
  },
};

/**
 * Thrown at construction time when a driver option is out of range or of
 * the wrong type (e.g. `bcrypt: { saltRounds: 99 }`). Failing fast here
 * prevents subtle runtime failures while hashing.
 */
export class PasswordOptionsError extends MaahesOptionsError {
  constructor(message: string) {
    super(message);
    this.name = "PasswordOptionsError";
  }
}

/**
 * Normalizes the `Password()` factory input into a {@link PasswordConfig}.
 *
 * @param input - Configuration object, JSON string, or path to a JSON file
 *   (`{ "password": { ... } }` wrappers are unpacked automatically).
 * @returns The raw user configuration (not yet merged with defaults).
 * @throws {Error} When the input is not an object, not valid JSON, or the
 *   JSON does not contain a configuration object.
 */
export function parseConfigInput(input?: PasswordConfig | string): PasswordConfig {
  if (!input) return {};

  if (typeof input === "object") {
    if (Array.isArray(input)) {
      throw new Error('Invalid password config: expected an object, got an array.');
    }
    return input;
  }

  const value = input.trim();
  let parsed: unknown;

  if (value.startsWith("{") || value.startsWith("[")) {
    parsed = JSON.parse(value);
  } else {
    parsed = JSON.parse(readFileSync(value, "utf8"));
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Invalid password config JSON: expected a JSON object.");
  }

  const root = parsed as { password?: unknown };
  const passwordConfig = root.password ?? parsed;

  if (typeof passwordConfig !== "object" || passwordConfig === null || Array.isArray(passwordConfig)) {
    throw new Error("Invalid password config: missing a 'password' configuration section.");
  }

  return passwordConfig as PasswordConfig;
}

/**
 * A resolved pepper keyring: the exact secret set a module can verify
 * against. `current` produces every new hash; `previous` only verifies.
 */
export interface PepperRing {
  /** The secret used for all new hashes. */
  current: PepperKey;
  /** Older secrets that may still verify legacy marked hashes. */
  previous: PepperKey[];
}

/**
 * Resolves the pepper configuration (config value, string shorthand or
 * environment fallback) into a validated {@link PepperRing}.
 *
 * Rules:
 * - a plain string is treated as the current secret with a derived id
 *   (first 8 hex chars of SHA-256 — the marker format used by
 *   Maahes ≤ 1.1, so existing hashes keep verifying);
 * - explicit keyring entries require a well-formed id and a non-empty
 *   secret; ids must be unique (no duplicates, no reuse of the current id
 *   among previous entries);
 * - no secret material ever appears in validation error messages.
 *
 * @param pepper - The user-provided pepper configuration (may be `undefined`).
 * @param env - The `PASSWORD_PEPPER` environment fallback.
 * @returns The resolved ring, or `undefined` when no pepper is configured.
 * @throws {PasswordOptionsError} When the pepper configuration is invalid.
 */
export function resolvePepper(
  pepper: PepperConfig | undefined,
  env: string | undefined
): PepperRing | undefined {
  if (pepper === undefined || pepper === null) {
    if (env !== undefined && env !== "") {
      return { current: { id: pepperId(env), secret: env }, previous: [] };
    }
    return undefined;
  }

  if (typeof pepper === "string") {
    if (pepper.length === 0) {
      throw new PasswordOptionsError("password.pepper must be a non-empty string.");
    }
    return { current: { id: pepperId(pepper), secret: pepper }, previous: [] };
  }

  if (typeof pepper !== "object" || Array.isArray(pepper)) {
    throw new PasswordOptionsError(
      "password.pepper must be a string or an object with a 'current' key."
    );
  }

  const validateKey = (key: unknown, path: string): PepperKey => {
    if (typeof key !== "object" || key === null || Array.isArray(key)) {
      throw new PasswordOptionsError(`${path} must be an object with 'id' and 'secret'.`);
    }
    const { id, secret } = key as Record<string, unknown>;
    if (typeof id !== "string" || !isValidPepperId(id)) {
      throw new PasswordOptionsError(
        `${path}.id must be a string of 1-32 characters (letters, digits, '_' or '-').`
      );
    }
    if (typeof secret !== "string" || secret.length === 0) {
      throw new PasswordOptionsError(`${path}.secret must be a non-empty string.`);
    }
    return { id, secret };
  };

  const current = validateKey(pepper.current, "password.pepper.current");

  const previousInput = pepper.previous;
  if (previousInput !== undefined && !Array.isArray(previousInput)) {
    throw new PasswordOptionsError("password.pepper.previous must be an array of pepper keys.");
  }

  const previous: PepperKey[] = [];
  const seen = new Set<string>([current.id]);
  for (const [index, key] of (previousInput ?? []).entries()) {
    const validated = validateKey(key, `password.pepper.previous[${index}]`);
    if (seen.has(validated.id)) {
      throw new PasswordOptionsError(
        `password.pepper.previous contains a duplicate pepper id "${validated.id}".`
      );
    }
    seen.add(validated.id);
    previous.push(validated);
  }

  return { current, previous };
}

/**
 * Merges user configuration over {@link DEFAULT_PASSWORD_CONFIG} with a
 * deep merge (nested objects merge field-by-field; arrays and primitives
 * replace). The pepper secret is left untouched here — it is resolved by
 * {@link resolvePepper} so the keyring can fall back to the
 * `PASSWORD_PEPPER` environment variable and validate at construction.
 *
 * @param user - Raw user configuration; every omitted field falls back to defaults.
 * @returns The fully-resolved configuration.
 */
export function mergeConfig(user: PasswordConfig = {}): PasswordConfig {
  return deepMerge(DEFAULT_PASSWORD_CONFIG, user);
}