/**
 * @fileoverview The `Csp()` factory — assembles the public module API
 * from resolved configuration and the pure engine.
 *
 * Mirrors the Password/CORS/Headers factory contract: `Csp()` for
 * defaults, `Csp(config)` for an object, JSON string or JSON file path,
 * and `Csp("raw policy string")` for a complete policy. Configuration
 * errors throw `CspOptionsError` at construction so misconfiguration
 * fails at boot, never in request handlers.
 *
 * @module csp/factory
 */

import { buildCsp } from "./core";
import { resolveCspConfig, type ResolvedCspConfig } from "./config";
import { parseCsp } from "./core";
import type { CspBuildContext, CspConfig, CspModule, CspPlan } from "./types";
import { parseCspConfigInput } from "./config";

/**
 * Creates an immutable CSP module bound to a configuration.
 *
 * @param input - Configuration object, inline JSON string, JSON file
 *   path, or a raw policy string. Omit for the `"default"` preset.
 * @returns The immutable, share-safe CSP module.
 * @throws {CspOptionsError} When the configuration is invalid.
 */
export function Csp(input?: CspConfig | string): CspModule {
  const config: ResolvedCspConfig = resolveCspConfig(parseCspConfigInput(input));

  /** Pure, deterministic resolution shared by every surface. */
  const build = (context?: CspBuildContext): CspPlan => buildCsp(config, context);

  return {
    build,
    headers: (context) => {
      const plan = build(context);
      const headers = new Headers();
      for (const [name, value] of Object.entries(plan.headers)) {
        headers.set(name, value);
      }
      return headers;
    },
    policy: (context) => Object.values(build(context).headers)[0] ?? "",
    parse: parseCsp,
  };
}

/** Re-export the canonical defaults, presets and helpers for introspection. */
export { DEFAULT_CSP_CONFIG, PRESETS as CSP_PRESETS, parseCspConfigInput, resolveCspConfig } from "./config";
export { CspOptionsError } from "./errors";