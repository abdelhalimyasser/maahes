/**
 * @fileoverview Defaults, presets, parsing and validation of the CORS
 * module configuration.
 *
 * Follows the Password module's config contract: a canonical defaults
 * object is the single source of truth; user config arrives as an
 * object, an inline JSON string or a JSON file path (an optional
 * `{"cors": ...}` wrapper is unwrapped); a deep merge resolves the
 * final configuration; invalid options throw `CorsOptionsError` at
 * construction so misconfiguration fails at boot.
 *
 * @module cors/config
 */

import { readFileSync } from "node:fs";
import { deepMerge } from "../shared/deepMerge";
import { MaahesOptionsError } from "../shared/errors";
import type { CorsConfig, CorsOriginRule } from "./types";

/** The canonical, fully-populated default CORS configuration. */
export const DEFAULT_CORS_CONFIG: Required<
  Pick<
    CorsConfig,
    | "matchMode"
    | "methods"
    | "exposedHeaders"
    | "credentials"
    | "maxAge"
    | "preflight"
    | "optionsSuccessStatus"
    | "allowPrivateNetwork"
    | "allowNullOrigin"
  >
> & {
  origin?: CorsConfig["origin"];
  allowlist?: CorsConfig["allowlist"];
  allowedHeaders: CorsConfig["allowedHeaders"];
  preset: NonNullable<CorsConfig["preset"]>;
  failureStatus?: number;
  onBlock?: CorsConfig["onBlock"];
  onPreflight?: CorsConfig["onPreflight"];
} = {
  origin: "*",
  allowlist: undefined,
  matchMode: "auto",
  methods: ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
  allowedHeaders: true, // reflect requested headers (credentials-safe wildcard)
  exposedHeaders: [],
  credentials: false,
  maxAge: 86400,
  preflight: "auto",
  optionsSuccessStatus: 204,
  allowPrivateNetwork: false,
  allowNullOrigin: false,
  failureStatus: undefined,
  preset: "default",
};

/**
 * Preset overrides applied on top of defaults before the user config is
 * merged, preserving the npm-`cors` package's observable behavior for
 * drop-in migrations: answer every OPTIONS request.
 */
const PRESETS: Record<NonNullable<CorsConfig["preset"]>, Partial<CorsConfig>> = {
  default: {},
  express: { preflight: "always" },
};

/**
 * Thrown at construction time when a CORS option is out of range, of the
 * wrong type or references an unknown enum value.
 */
export class CorsOptionsError extends MaahesOptionsError {
  constructor(message: string) {
    super(message);
    this.name = "CorsOptionsError";
  }
}

/**
 * Normalizes the {@link Cors} factory input into a {@link CorsConfig}.
 *
 * @param input - Config object, JSON string, or path to a JSON file
 *   (`{"cors": {...}}` wrappers are unpacked automatically).
 * @returns The raw user configuration (not yet merged with defaults).
 * @throws {CorsOptionsError} When the input is not a config object.
 */
export function parseCorsConfigInput(input?: CorsConfig | string): CorsConfig {
  if (!input) return {};

  if (typeof input === "object") {
    if (Array.isArray(input)) {
      throw new CorsOptionsError("Invalid cors config: expected an object, got an array.");
    }
    return input;
  }

  const value = input.trim();
  let parsed: unknown;

  try {
    parsed = JSON.parse(value);
  } catch {
    parsed = JSON.parse(readFileSync(value, "utf8"));
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new CorsOptionsError("Invalid cors config JSON: expected a JSON object.");
  }

  const root = parsed as { cors?: unknown };
  const corsConfig = root.cors ?? parsed;

  if (typeof corsConfig !== "object" || corsConfig === null || Array.isArray(corsConfig)) {
    throw new CorsOptionsError("Invalid cors config: missing a 'cors' configuration section.");
  }

  return corsConfig as CorsConfig;
}

/**
 * Validates a resolved CORS configuration, failing fast on anything the
 * engine could not honor.
 *
 * @param config - Fully-resolved configuration.
 * @throws {CorsOptionsError} On the first invalid option.
 */
export function validateConfig(config: CorsConfig): void {
  const invalid = (message: string): never => {
    throw new CorsOptionsError(message);
  };

  if (config.matchMode !== undefined && !["exact", "glob", "regex", "auto"].includes(config.matchMode)) {
    invalid(`cors.matchMode must be "exact", "glob", "regex" or "auto" (got ${config.matchMode}).`);
  }
  if (config.preflight !== undefined && !["auto", "always", "never"].includes(config.preflight)) {
    invalid(`cors.preflight must be "auto", "always" or "never" (got ${config.preflight}).`);
  }
  if (config.credentials !== undefined && typeof config.credentials !== "boolean") {
    invalid(`cors.credentials must be a boolean (got ${config.credentials}).`);
  }
  if (config.allowPrivateNetwork !== undefined && typeof config.allowPrivateNetwork !== "boolean") {
    invalid(`cors.allowPrivateNetwork must be a boolean (got ${config.allowPrivateNetwork}).`);
  }
  if (config.allowNullOrigin !== undefined && typeof config.allowNullOrigin !== "boolean") {
    invalid(`cors.allowNullOrigin must be a boolean (got ${config.allowNullOrigin}).`);
  }
  if (config.optionsSuccessStatus !== undefined) {
    const status = config.optionsSuccessStatus;
    if (!Number.isInteger(status) || status < 200 || status > 599) {
      invalid(`cors.optionsSuccessStatus must be an integer between 200 and 599 (got ${status}).`);
    }
  }
  if (config.failureStatus !== undefined) {
    const status = config.failureStatus;
    if (!Number.isInteger(status) || status < 200 || status > 599) {
      invalid(`cors.failureStatus must be an integer between 200 and 599 (got ${status}).`);
    }
  }
  if (config.maxAge !== undefined && (!Number.isInteger(config.maxAge) || config.maxAge < 0)) {
    invalid(`cors.maxAge must be a non-negative integer of seconds (got ${config.maxAge}).`);
  }
  if (config.methods !== undefined) {
    if (!Array.isArray(config.methods) || config.methods.length === 0) {
      invalid("cors.methods must be a non-empty string array.");
    }
    for (const method of config.methods) {
      if (typeof method !== "string" || method.trim() === "" || /\s/.test(method)) {
        invalid(`cors.methods entries must be non-empty strings without whitespace (got ${JSON.stringify(method)}).`);
      }
    }
  }
  if (config.allowedHeaders !== undefined && config.allowedHeaders !== true) {
    if (!Array.isArray(config.allowedHeaders)) {
      invalid("cors.allowedHeaders must be a string array or true.");
    }
    for (const name of config.allowedHeaders) {
      if (typeof name !== "string" || name.trim() === "") {
        invalid(`cors.allowedHeaders entries must be non-empty strings (got ${JSON.stringify(name)}).`);
      }
    }
  }
  if (config.exposedHeaders !== undefined && !Array.isArray(config.exposedHeaders)) {
    invalid("cors.exposedHeaders must be a string array.");
  }
  if (config.origin !== undefined && typeof config.origin !== "string" && !Array.isArray(config.origin) && !(config.origin instanceof RegExp) && typeof config.origin !== "function") {
    invalid("cors.origin must be a string, string array, RegExp, origin-rule array or callback function.");
  }
  if (config.allowlist !== undefined && !Array.isArray(config.allowlist)) {
    invalid("cors.allowlist must be an array of strings or origin rules.");
  }
  if (config.preset !== undefined && !["default", "express"].includes(config.preset)) {
    invalid(`cors.preset must be "default" or "express" (got ${config.preset}).`);
  }
}

/**
 * Resolves the effective configuration: defaults → preset → user
 * overrides (deep merged, so partial configs keep every untouched
 * default). `allowlist` entries are folded into `origin`.
 *
 * @param user - Raw user configuration.
 * @returns The fully-resolved configuration, validated.
 * @throws {CorsOptionsError} When options are invalid.
 */
export function resolveConfig(user: CorsConfig = {}): CorsConfig {
  const presetOverrides = PRESETS[user.preset ?? "default"];

  const base = deepMerge(
    DEFAULT_CORS_CONFIG as unknown as Record<string, unknown>,
    presetOverrides as Partial<Record<string, unknown>>
  ) as CorsConfig;
  const merged = deepMerge(
    base as unknown as Record<string, unknown>,
    user as unknown as Partial<Record<string, unknown>>
  ) as CorsConfig;

  if (merged.allowlist !== undefined) {
    if (!Array.isArray(merged.allowlist)) {
      throw new CorsOptionsError("cors.allowlist must be an array of strings or origin rules.");
    }
    const origin = merged.origin;
    const allowlist: Array<string | CorsOriginRule> = merged.allowlist;
    let resolved: CorsConfig["origin"];
    if (origin === undefined || origin === "*") {
      resolved = allowlist as CorsConfig["origin"];
    } else if (Array.isArray(origin)) {
      resolved = [...origin, ...allowlist] as CorsConfig["origin"];
    } else {
      resolved = [origin, ...allowlist] as CorsConfig["origin"];
    }
    merged.origin = resolved;
  }
  merged.allowlist = undefined;

  validateConfig(merged);
  return merged;
}