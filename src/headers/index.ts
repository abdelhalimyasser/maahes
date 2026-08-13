/**
 * @fileoverview Public surface of the Maahes security headers module.
 *
 * @example
 * import { SecurityHeaders } from "@maahes/core";
 *
 * const headers = SecurityHeaders({ preset: "strict" });
 *
 * // Express / Connect
 * app.use(headers.middleware());
 *
 * // Web-standard / Bun / edge
 * server.fetch = headers.fetchHandler(route);
 *
 * // Pure, deterministic header set
 * const plan = headers.build({ secure: true });
 * @module headers
 */

export { SecurityHeaders } from "./factory";
export {
  DEFAULT_HEADERS_CONFIG,
  PRESETS,
  parseHeadersConfigInput,
  resolveHeadersConfig,
} from "./config";
export type { ResolvedSecurityHeadersConfig } from "./config";
export { buildHeaderSet, KNOWN_HEADER_ORDER, normalizeExisting } from "./core";
export { SecurityHeadersOptionsError } from "./errors";
export type {
  CoepValue,
  CoopValue,
  CorpValue,
  CrossDomainPolicyValue,
  FrameOptionsValue,
  HeaderBuildContext,
  HeaderPlan,
  HeadersRequestLike,
  HeadersResponseLike,
  HstsConfig,
  ReferrerPolicyValue,
  SecurityHeadersConfig,
  SecurityHeadersMiddleware,
  SecurityHeadersModule,
  SecurityHeadersNextCallback,
  SecurityHeadersPreset,
  XssProtectionValue,
} from "./types";