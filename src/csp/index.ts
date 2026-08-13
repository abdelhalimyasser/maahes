/**
 * @fileoverview Public surface of the Maahes CSP module.
 *
 * @example
 * import { Csp } from "@maahes/core";
 *
 * // Strict, nonce-based policy (Google's strict-dynamic pattern)
 * const csp = Csp({ preset: "strict" });
 * const { headers } = csp.build({ nonce: reqNonce }); // per request
 *
 * // Static policy, wired straight into SecurityHeaders:
 * const headers = SecurityHeaders({ csp: Csp({ preset: "default" }).policy() });
 *
 * // Audit an existing policy
 * csp.parse("default-src 'self'; frame-ancestors 'none'");
 * @module csp
 */

export { Csp } from "./factory";
export {
  DEFAULT_CSP_CONFIG,
  PRESETS as CSP_PRESETS,
  cspPolicyOf,
  parseCspConfigInput,
  resolveCspConfig,
} from "./config";
export type { ResolvedCspConfig } from "./config";
export { buildCsp, CSP_HEADER, CSP_REPORT_ONLY_HEADER, parseCsp, serializeCsp, validateSource } from "./core";
export { CspOptionsError } from "./errors";
export type {
  CspBuildContext,
  CspConfig,
  CspDirectives,
  CspModule,
  CspParsed,
  CspPlan,
  CspPreset,
  CspSource,
} from "./types";