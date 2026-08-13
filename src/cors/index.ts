/**
 * @fileoverview Public surface of the Maahes CORS module.
 *
 * @example
 * import { Cors } from "@maahes/core";
 *
 * const cors = Cors({
 *   origin: ["https://app.example.com", "https://*.example.com"],
 *   credentials: true,
 * });
 *
 * // Express
 * app.use(cors.middleware());
 *
 * // Web-standard / Bun / edge
 * server.fetch = cors.fetchHandler(route);
 * @module cors
 */

export { Cors } from "./factory";
export { CorsOptionsError, DEFAULT_CORS_CONFIG, parseCorsConfigInput, resolveConfig } from "./config";
export {
  createEngine,
  existingVary,
  headerValue,
  isHeaderSubset,
  isPreflight,
  mergeVary,
  parseCsv,
  sortHeaderNames,
  sortMethods,
} from "./core";
export { compileEntry, compileGlob, compileOrigin, normalizeOrigin } from "./matchers";
export type {
  CorsBlockContext,
  CorsConfig,
  CorsHeadersInput,
  CorsMatchMode,
  CorsMiddleware,
  CorsModule,
  CorsNextCallback,
  CorsOriginCallback,
  CorsOriginRule,
  CorsPreflightContext,
  CorsPreflightMode,
  CorsRequestInput,
  CorsRequestLike,
  CorsResult,
  IncomingMessageLike,
  ServerResponseLike,
} from "./types";