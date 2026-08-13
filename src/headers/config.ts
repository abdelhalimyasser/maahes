/**
 * @fileoverview Defaults, presets, parsing and validation of the security
 * headers configuration.
 *
 * Follows the Password/CORS config contract: a canonical defaults object
 * is the single source of truth; user config arrives as an object, an
 * inline JSON string or a JSON file path (an optional `{"headers": ...}`
 * wrapper is unwrapped); a deep merge resolves the final configuration;
 * invalid options throw `SecurityHeadersOptionsError` at construction so
 * misconfiguration fails at boot, never in a request handler.
 *
 * @module headers/config
 */

import { readFileSync } from "node:fs";
import { deepMerge } from "../shared/deepMerge";
import { KNOWN_HEADER_ORDER } from "./core";
import { SecurityHeadersOptionsError } from "./errors";
import type {
  HstsConfig,
  ReferrerPolicyValue,
  SecurityHeadersConfig,
  SecurityHeadersPreset,
} from "./types";

/** The canonical, fully-populated base configuration (the `"default"` preset). */
export const DEFAULT_HEADERS_CONFIG: ResolvedSecurityHeadersConfig = {
  preset: "default",
  httpsOnly: true,
  overwrite: true,
  remove: [],
  extra: {},
  nosniff: true,
  frameOptions: "DENY",
  referrerPolicy: "strict-origin-when-cross-origin",
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
  coop: "same-origin",
  coep: "credentialless",
  corp: false,
  permissionsPolicy: "camera=(), microphone=(), geolocation=()",
  xssProtection: "0",
  crossDomainPolicy: "none",
  dnsPrefetchControl: false,
  originAgentCluster: false,
};

/**
 * Preset overrides applied on top of the base configuration.
 *
 * - `minimal`: only the least-invasive hardening headers. HSTS is still
 *   emitted (in secure contexts) because its absence is a real risk;
 *   everything else that could affect page behavior stays off.
 * - `default`: minimal + cross-origin isolation (COOP/COEP) with the
 *   compatibility-friendly `credentialless`, a conservative
 *   `Permissions-Policy` and legacy-filter hardening.
 *   `Cross-Origin-Resource-Policy` stays OFF because `same-origin` on
 *   shared resources breaks legitimate cross-origin consumers.
 * - `strict`: default + `Cross-Origin-Resource-Policy: same-origin` and
 *   the strictest referrer policy. Requires auditing every resource
 *   your application serves or embeds.
 *
 * There is no universally correct header configuration — presets are a
 * starting point; review the compatibility notes in `docs/headers.md`.
 */
export const PRESETS: Record<SecurityHeadersPreset, Partial<ResolvedSecurityHeadersConfig>> = {
  minimal: {
    coop: false,
    coep: false,
    permissionsPolicy: false,
    xssProtection: false,
    crossDomainPolicy: false,
  },
  default: {},
  strict: {
    corp: "same-origin",
    referrerPolicy: "no-referrer",
  },
};

/** The fully-resolved, all-fields-present configuration shape. */
export interface ResolvedSecurityHeadersConfig {
  preset: SecurityHeadersPreset;
  httpsOnly: boolean;
  overwrite: boolean;
  remove: string[];
  extra: Record<string, string>;
  nosniff: boolean;
  frameOptions: "DENY" | "SAMEORIGIN" | false;
  referrerPolicy: ReferrerPolicyValue | false;
  hsts: HstsConfig | false;
  coop: "same-origin" | "same-origin-allow-popups" | "unsafe-none" | false;
  coep: "require-corp" | "credentialless" | "unsafe-none" | false;
  corp: "same-origin" | "same-site" | "cross-origin" | false;
  permissionsPolicy: string | false;
  xssProtection: "0" | "1" | "1; mode=block" | false;
  crossDomainPolicy: "none" | "master-only" | "by-content-type" | "all" | false;
  dnsPrefetchControl: boolean;
  originAgentCluster: boolean;
}

/** RFC 7230 token — valid header name characters. */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** Control characters forbidden in header values (tab is allowed). */
const FORBIDDEN_VALUE_CHARS = /[\u0000-\u0008\u000A-\u001F\u007F]/;
/** Minimum HSTS maxAge accepted when `preload` is requested (1 year, per preload-list requirements). */
const PRELOAD_MIN_MAX_AGE = 31536000;
/** Maximum HSTS maxAge (2^31 - 129 seconds ≈ 68 years, per RFC 6797 §6.1). */
const HSTS_MAX_MAX_AGE = 631138519;

const REFERRER_POLICIES = new Set<ReferrerPolicyValue>([
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
]);

/**
 * Normalizes the {@link SecurityHeaders} factory input into a
 * {@link SecurityHeadersConfig}.
 *
 * @param input - Config object, JSON string, or path to a JSON file
 *   (`{"headers": {...}}` wrappers are unpacked automatically).
 * @returns The raw user configuration (not yet merged with defaults).
 * @throws {SecurityHeadersOptionsError} When the input is not a config object.
 */
export function parseHeadersConfigInput(input?: SecurityHeadersConfig | string): SecurityHeadersConfig {
  if (!input) return {};

  if (typeof input === "object") {
    if (Array.isArray(input)) {
      throw new SecurityHeadersOptionsError("Invalid security headers config: expected an object, got an array.");
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
    throw new SecurityHeadersOptionsError("Invalid security headers config JSON: expected a JSON object.");
  }

  const root = parsed as { headers?: unknown };
  const headersConfig = root.headers ?? parsed;

  if (typeof headersConfig !== "object" || headersConfig === null || Array.isArray(headersConfig)) {
    throw new SecurityHeadersOptionsError("Invalid security headers config: missing a 'headers' section.");
  }

  return headersConfig as SecurityHeadersConfig;
}

/**
 * Validates a resolved security headers configuration, failing fast on
 * anything the engine could not emit safely.
 *
 * @param config - Fully-resolved configuration.
 * @throws {SecurityHeadersOptionsError} On the first invalid option.
 */
export function validateConfig(config: ResolvedSecurityHeadersConfig): void {
  const invalid = (message: string): never => {
    throw new SecurityHeadersOptionsError(message);
  };

  if (!["minimal", "default", "strict"].includes(config.preset)) {
    invalid(`headers.preset must be "minimal", "default" or "strict" (got ${config.preset}).`);
  }
  for (const key of ["httpsOnly", "overwrite", "nosniff", "dnsPrefetchControl", "originAgentCluster"] as const) {
    if (typeof config[key] !== "boolean") {
      invalid(`headers.${key} must be a boolean (got ${config[key]}).`);
    }
  }

  if (config.frameOptions !== false && !["DENY", "SAMEORIGIN"].includes(config.frameOptions)) {
    invalid(`headers.frameOptions must be "DENY", "SAMEORIGIN" or false (got ${config.frameOptions}).`);
  }
  if (config.referrerPolicy !== false && !REFERRER_POLICIES.has(config.referrerPolicy)) {
    invalid(
      `headers.referrerPolicy must be one of ${[...REFERRER_POLICIES].join(", ")} or false (got ${config.referrerPolicy}).`
    );
  }
  if (config.coop !== false && !["same-origin", "same-origin-allow-popups", "unsafe-none"].includes(config.coop)) {
    invalid(
      `headers.coop must be "same-origin", "same-origin-allow-popups", "unsafe-none" or false (got ${config.coop}).`
    );
  }
  if (config.coep !== false && !["require-corp", "credentialless", "unsafe-none"].includes(config.coep)) {
    invalid(
      `headers.coep must be "require-corp", "credentialless", "unsafe-none" or false (got ${config.coep}).`
    );
  }
  if (config.corp !== false && !["same-origin", "same-site", "cross-origin"].includes(config.corp)) {
    invalid(`headers.corp must be "same-origin", "same-site", "cross-origin" or false (got ${config.corp}).`);
  }
  if (config.xssProtection !== false && !["0", "1", "1; mode=block"].includes(config.xssProtection)) {
    invalid(`headers.xssProtection must be "0", "1", "1; mode=block" or false (got ${config.xssProtection}).`);
  }
  if (
    config.crossDomainPolicy !== false &&
    !["none", "master-only", "by-content-type", "all"].includes(config.crossDomainPolicy)
  ) {
    invalid(
      `headers.crossDomainPolicy must be "none", "master-only", "by-content-type", "all" or false (got ${config.crossDomainPolicy}).`
    );
  }
  if (config.permissionsPolicy !== false && typeof config.permissionsPolicy !== "string") {
    invalid(`headers.permissionsPolicy must be a policy string or false (got ${config.permissionsPolicy}).`);
  }
  if (config.permissionsPolicy && FORBIDDEN_VALUE_CHARS.test(config.permissionsPolicy)) {
    invalid("headers.permissionsPolicy must not contain control characters.");
  }

  if (config.hsts !== false) {
    const hsts = config.hsts;
    if (!Number.isInteger(hsts.maxAge) || hsts.maxAge < 0) {
      invalid(`headers.hsts.maxAge must be a non-negative integer of seconds (got ${hsts.maxAge}).`);
    }
    if (hsts.maxAge > HSTS_MAX_MAX_AGE) {
      invalid(
        `headers.hsts.maxAge must not exceed ${HSTS_MAX_MAX_AGE} seconds (RFC 6797 §6.1, got ${hsts.maxAge}).`
      );
    }
    if (typeof hsts.includeSubDomains !== "boolean") {
      invalid(`headers.hsts.includeSubDomains must be a boolean (got ${hsts.includeSubDomains}).`);
    }
    if (typeof hsts.preload !== "boolean") {
      invalid(`headers.hsts.preload must be a boolean (got ${hsts.preload}).`);
    }
    if (hsts.preload && (hsts.maxAge < PRELOAD_MIN_MAX_AGE || !hsts.includeSubDomains)) {
      invalid(
        `headers.hsts.preload requires maxAge >= ${PRELOAD_MIN_MAX_AGE} and includeSubDomains: true (got maxAge=${hsts.maxAge}, includeSubDomains=${hsts.includeSubDomains}).`
      );
    }
  }

  if (!Array.isArray(config.remove)) {
    invalid("headers.remove must be an array of header names.");
  }
  for (const name of config.remove) {
    if (typeof name !== "string" || !HEADER_NAME_RE.test(name)) {
      invalid(`headers.remove entries must be valid header names (got ${JSON.stringify(name)}).`);
    }
  }

  if (typeof config.extra !== "object" || config.extra === null || Array.isArray(config.extra)) {
    invalid("headers.extra must be an object mapping header names to values.");
  }
  const removedLower = new Set(config.remove.map((name) => name.toLowerCase()));
  for (const [name, value] of Object.entries(config.extra)) {
    if (!HEADER_NAME_RE.test(name)) {
      invalid(`headers.extra contains an invalid header name (got ${JSON.stringify(name)}).`);
    }
    if (removedLower.has(name.toLowerCase())) {
      invalid(`headers.extra must not override a removed header (conflict on "${name}").`);
    }
    if (KNOWN_HEADER_ORDER.some((known) => known.toLowerCase() === name.toLowerCase())) {
      invalid(
        `headers.extra must not override an engine-owned header ("${name}" is configured via its own option).`
      );
    }
    if (typeof value !== "string") {
      invalid(`headers.extra values must be strings (got ${JSON.stringify(value)} for "${name}").`);
    }
    if (FORBIDDEN_VALUE_CHARS.test(value)) {
      invalid(`headers.extra values must not contain control characters (header "${name}").`);
    }
  }
}

/**
 * Resolves the effective configuration: defaults → preset → user
 * overrides (deep merged, so partial configs keep every untouched
 * default), then validated.
 *
 * @param user - Raw user configuration.
 * @returns The fully-resolved, validated configuration.
 * @throws {SecurityHeadersOptionsError} When options are invalid.
 */
export function resolveHeadersConfig(user: SecurityHeadersConfig = {}): ResolvedSecurityHeadersConfig {
  const preset = user.preset ?? "default";
  const presetOverrides = PRESETS[preset] ?? {};

  const base = deepMerge(
    DEFAULT_HEADERS_CONFIG as unknown as Record<string, unknown>,
    presetOverrides as unknown as Partial<Record<string, unknown>>
  ) as unknown as ResolvedSecurityHeadersConfig;
  const merged = deepMerge(
    base as unknown as Record<string, unknown>,
    user as unknown as Partial<Record<string, unknown>>
  ) as unknown as ResolvedSecurityHeadersConfig;

  validateConfig(merged);
  return merged;
}