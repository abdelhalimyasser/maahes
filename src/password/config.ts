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
import type { PasswordConfig } from "./types";

/**
 * The canonical, fully-populated default configuration of the password
 * module. This is the single source of truth for every default value;
 * drivers and policy components never re-declare defaults of their own
 * (beyond defensive fallbacks), so option handling cannot drift.
 */
export const DEFAULT_PASSWORD_CONFIG: Required<Omit<PasswordConfig, "pepper">> & {
  /** Peppering secret; intentionally optional and resolved from the environment as a fallback. */
  pepper?: string;
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
    allowedScripts: ["Latin"],
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
export class PasswordOptionsError extends Error {
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
 * Merges user configuration over {@link DEFAULT_PASSWORD_CONFIG} with a
 * deep merge (nested objects merge field-by-field; arrays and primitives
 * replace). The pepper secret resolves from the config or the
 * `PASSWORD_PEPPER` environment variable.
 *
 * @param user - Raw user configuration; every omitted field falls back to defaults.
 * @returns The fully-resolved configuration.
 */
export function mergeConfig(user: PasswordConfig = {}): PasswordConfig {
  const merged = deepMerge(DEFAULT_PASSWORD_CONFIG, user);
  merged.pepper = user.pepper ?? process.env.PASSWORD_PEPPER;
  return merged;
}