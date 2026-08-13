/**
 * @fileoverview Defaults, presets, parsing and validation of the CSP
 * configuration.
 *
 * Follows the Password/CORS/Headers config contract: a canonical
 * defaults object is the single source of truth; user config arrives as
 * an object, an inline JSON string or a JSON file path (an optional
 * `{"csp": ...}` wrapper is unwrapped); a deep merge resolves the final
 * configuration; invalid options throw `CspOptionsError` at
 * construction so misconfiguration fails at boot, never at request time.
 *
 * String input with a non-JSON, non-file shape is treated as a RAW
 * policy string (`Csp("default-src 'self'")`) — a complete directive
 * map that replaces the defaults entirely.
 *
 * @module csp/config
 */

import { readFileSync } from "node:fs";
import { deepMerge } from "../shared/deepMerge";
import { parseCsp, serializeCsp, validateSource } from "./core";
import { CspOptionsError } from "./errors";
import type { CspConfig, CspPreset, CspSource } from "./types";

/** The canonical, fully-populated base configuration (the `"default"` preset). */
export const DEFAULT_CSP_CONFIG: ResolvedCspConfig = {
  preset: "default",
  directives: {
    "base-uri": ["'self'"],
    "default-src": ["'self'"],
    "frame-ancestors": ["'none'"],
    "object-src": ["'none'"],
  },
  reportOnly: false,
};

/**
 * Non-enumerable marker set by {@link parseCspConfigInput} on configs
 * parsed from a raw policy string: their directive map is the COMPLETE
 * policy and must not be merged over presets.
 */
const RAW_POLICY: unique symbol = Symbol("maahes.csp.rawPolicy");

/**
 * Preset overrides applied on top of the base configuration.
 *
 * - `minimal`: the least-invasive hardening — nothing that affects how
 *   scripts/styles load. Blocks clickjacking (`frame-ancestors`),
 *   plugin content (`object-src`) and base-URI hijacking (`base-uri`).
 * - `default`: minimal + `default-src 'self'`. Requires first-party
 *   assets only; relax `default-src` (or add `script-src`/`style-src`)
 *   for CDN-loaded content.
 * - `strict`: the modern strict-dynamic pattern (Google CSP guide):
 *   nonce-based `script-src` with `'strict-dynamic'` and a hardened
 *   baseline. `build()` without a nonce throws — by design.
 *
 * Explicit directives always beat the preset (per directive name).
 */
export const PRESETS: Record<CspPreset, { directives?: Record<string, CspSource[]> }> = {
  minimal: {
    directives: {
      "base-uri": ["'self'"],
      "frame-ancestors": ["'none'"],
      "object-src": ["'none'"],
    },
  },
  default: {},
  strict: {
    directives: {
      "base-uri": ["'self'"],
      "default-src": ["'self'"],
      "frame-ancestors": ["'none'"],
      "object-src": ["'none'"],
      "script-src": ["'nonce-$nonce'", "'strict-dynamic'"],
    },
  },
};

/** The fully-resolved, all-fields-present configuration shape. */
export interface ResolvedCspConfig {
  preset: CspPreset;
  /** Directive name → ordered sources (already normalized & validated). */
  directives: Record<string, string[]>;
  reportOnly: boolean;
}

/**
 * Normalizes the {@link Csp} factory input into a {@link CspConfig}.
 *
 * @param input - Config object, JSON string, JSON file path, or a raw
 *   policy string.
 * @returns The raw user configuration (not yet merged with defaults).
 * @throws {CspOptionsError} When the input is not a valid config.
 */
export function parseCspConfigInput(input?: CspConfig | string): CspConfig {
  if (input === undefined) return {};

  if (typeof input === "object") {
    if (Array.isArray(input)) {
      throw new CspOptionsError("Invalid CSP config: expected an object, got an array.");
    }
    return input;
  }

  const value = input.trim();
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(value);
  } catch {
    try {
      parsed = JSON.parse(readFileSync(value, "utf8"));
    } catch {
      // Not JSON, not a file: treat as a raw policy string. Its
      // directive map replaces the defaults entirely.
      const { directives } = parseCsp(value);
      const raw: CspConfig = { directives };
      Object.defineProperty(raw, RAW_POLICY, { value: true, enumerable: false });
      return raw;
    }
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new CspOptionsError("Invalid CSP config JSON: expected a JSON object.");
  }

  const root = parsed as { csp?: unknown };
  const cspConfig = root.csp ?? parsed;

  if (typeof cspConfig !== "object" || cspConfig === null || Array.isArray(cspConfig)) {
    throw new CspOptionsError("Invalid CSP config: missing a 'csp' section.");
  }

  return cspConfig as CspConfig;
}

/**
 * Validates a resolved CSP configuration, failing fast on anything the
 * engine could not emit safely.
 *
 * @param config - Fully-resolved configuration.
 * @throws {CspOptionsError} On the first invalid option.
 */
export function validateCspConfig(config: ResolvedCspConfig): void {
  const invalid = (message: string): never => {
    throw new CspOptionsError(message);
  };

  if (!["minimal", "default", "strict"].includes(config.preset)) {
    invalid(`csp.preset must be "minimal", "default" or "strict" (got ${config.preset}).`);
  }
  if (typeof config.reportOnly !== "boolean") {
    invalid(`csp.reportOnly must be a boolean (got ${config.reportOnly}).`);
  }
  if (typeof config.directives !== "object" || config.directives === null || Array.isArray(config.directives)) {
    invalid("csp.directives must be an object mapping directive names to source lists.");
  }

  for (const [rawName, rawSources] of Object.entries(config.directives)) {
    const name = rawName.toLowerCase();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
      invalid(`csp.directives contains an invalid directive name (got ${JSON.stringify(rawName)}).`);
    }

    const sources = Array.isArray(rawSources) ? rawSources : [rawSources];
    for (const source of sources) {
      validateSource(name, source);
    }
    if (sources.includes("'none'") && sources.length > 1) {
      invalid(`csp.${name} may only contain 'none' as its sole source.`);
    }
  }
}

/**
 * Resolves the effective configuration: presets REPLACE the default
 * directive map wholesale (a preset's directives are its complete set);
 * user directives then merge per directive name over the preset's map.
 *
 * Raw policy strings (a non-JSON, non-file string input) bypass both —
 * their directive map is the complete policy, exactly as written.
 *
 * @param user - Raw user configuration.
 * @returns The fully-resolved, validated configuration.
 * @throws {CspOptionsError} When options are invalid.
 */
export function resolveCspConfig(user: CspConfig = {}): ResolvedCspConfig {
  const isRaw = (user as Record<PropertyKey, unknown>)[RAW_POLICY] === true;

  let merged: ResolvedCspConfig;
  if (isRaw) {
    merged = {
      preset: "default",
      directives: {},
      reportOnly: false,
    };
  } else {
    const preset = user.preset ?? "default";
    const presetDirectives =
      preset === "default"
        ? { ...DEFAULT_CSP_CONFIG.directives }
        : { ...(PRESETS[preset]?.directives ?? {}) };
    merged = deepMerge(
      { ...DEFAULT_CSP_CONFIG, directives: presetDirectives } as unknown as Record<string, unknown>,
      {}
    ) as unknown as ResolvedCspConfig;
  }

  const final = deepMerge(
    merged as unknown as Record<string, unknown>,
    user as unknown as Record<string, unknown>
  ) as unknown as ResolvedCspConfig;

  if (Array.isArray(final.directives)) {
    throw new CspOptionsError("csp.directives must be an object mapping directive names to source lists.");
  }

  // Normalize directive values to ordered string arrays and names to lowercase.
  const directives: Record<string, string[]> = {};
  for (const [rawName, rawSources] of Object.entries(final.directives)) {
    if (Array.isArray(rawSources)) {
      for (const source of rawSources) {
        if (typeof source !== "string") {
          throw new CspOptionsError(
            `csp.${rawName} sources must be strings (got ${JSON.stringify(source)}).`
          );
        }
      }
      directives[rawName.toLowerCase()] = rawSources as string[];
    } else if (typeof rawSources === "string") {
      directives[rawName.toLowerCase()] = [rawSources];
    } else {
      throw new CspOptionsError(
        `csp.${rawName} must be a string or an array of strings (got ${JSON.stringify(rawSources)}).`
      );
    }
  }
  final.directives = directives;

  validateCspConfig(final);
  return final;
}

/** Serializes a resolved CSP config to its policy string. */
export function cspPolicyOf(config: ResolvedCspConfig): string {
  return serializeCsp(config.directives);
}

export { parseCsp as parseCspPolicy } from "./core";