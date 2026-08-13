/**
 * @fileoverview The `SecurityHeaders()` factory — assembles the public
 * module API from resolved configuration and the pure engine.
 *
 * The public factory is deliberately named `SecurityHeaders`, NOT
 * `Headers`, because the Web Platform already exposes a global `Headers`
 * type/constructor.
 *
 * Mirrors the Password/CORS factory contract: `SecurityHeaders()` for
 * defaults, `SecurityHeaders(config)` for an object, JSON string or
 * JSON file path; configuration errors throw
 * `SecurityHeadersOptionsError` at construction so misconfiguration
 * fails at boot, never in request handlers.
 *
 * @module headers/factory
 */

import { parseHeadersConfigInput, resolveHeadersConfig, type ResolvedSecurityHeadersConfig } from "./config";
import { buildHeaderSet } from "./core";
import { createFetchHandler } from "./fetch";
import { createMiddleware } from "./middleware";
import type { HeaderBuildContext, HeaderPlan, SecurityHeadersConfig, SecurityHeadersModule } from "./types";

/**
 * Creates an immutable security headers module bound to a configuration.
 *
 * @param input - Configuration object, inline JSON string, or path to a
 *   JSON file (an optional `{"headers": ...}` wrapper is unpacked).
 *   Omit for the `"default"` preset.
 * @returns The immutable, share-safe security headers module.
 * @throws {SecurityHeadersOptionsError} When the configuration is invalid.
 */
export function SecurityHeaders(input?: SecurityHeadersConfig | string): SecurityHeadersModule {
  const config: ResolvedSecurityHeadersConfig = resolveHeadersConfig(parseHeadersConfigInput(input));

  /** Pure, deterministic resolution shared by every surface. */
  const build = (context?: HeaderBuildContext): HeaderPlan => buildHeaderSet(config, context);

  return {
    build,
    headers: (context) => {
      const plan = build(context);
      const headers = new Headers();
      for (const name of plan.removed) headers.delete(name);
      for (const [name, value] of Object.entries(plan.headers)) {
        headers.set(name, value);
      }
      return headers;
    },
    middleware: () => createMiddleware(config, build),
    fetchHandler: (handler) => createFetchHandler(config, build, handler),
  };
}

/** Re-export the canonical defaults, presets and error for introspection. */
export {
  DEFAULT_HEADERS_CONFIG,
  PRESETS,
  parseHeadersConfigInput,
  resolveHeadersConfig,
} from "./config";
export { SecurityHeadersOptionsError } from "./errors";