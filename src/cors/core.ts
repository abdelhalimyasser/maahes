/**
 * @fileoverview The pure CORS engine: request → structured result.
 *
 * No framework types, no I/O, no side effects besides the optional
 * user hooks. Given a resolved configuration and its compiled origin
 * matcher, it resolves the origin, detects/validates preflights,
 * enforces Private Network Access rules and builds the exact header
 * set (including merged `Vary`) in a deterministic order. The same
 * engine drives the middleware, the `node:http` handler and the fetch
 * wrapper.
 *
 * @module cors/core
 */

import { resolveOrigin, type CompiledOrigin } from "./matchers";
import type {
  CorsConfig,
  CorsPreflightMode,
  CorsRequestInput,
  CorsResult,
} from "./types";

/** Canonical header names the engine reads (lower-cased). */
export const HEADER_ORIGIN = "origin";
export const HEADER_VARY = "vary";
export const HEADER_ACRM = "access-control-request-method";
export const HEADER_ACRH = "access-control-request-headers";
export const HEADER_ACRPN = "access-control-request-private-network";

/** Response header names, emitted in this fixed order. */
export const RESPONSE_HEADERS = [
  "Access-Control-Allow-Origin",
  "Access-Control-Expose-Headers",
  "Access-Control-Allow-Credentials",
  "Access-Control-Allow-Methods",
  "Access-Control-Allow-Headers",
  "Access-Control-Allow-Private-Network",
  "Access-Control-Max-Age",
  "Vary",
] as const;

const PREFLIGHT_VARY = [
  "Origin",
  "Access-Control-Request-Method",
  "Access-Control-Request-Headers",
] as const;

/** How denied requests are represented to downstream hops. */
export interface BlockedRequest {
  blocked: true;
  statusCode?: number;
  headers: CorsResult["headers"];
  preflight: boolean;
}

/** Internal, resolved request state shared by the sync and async paths. */
interface ResolvedState {
  /** Raw origin from header/input. */
  origin: string | undefined;
  /** Origin string to reflect, when a callback resolved one. */
  reflectOrigin?: string;
  /** Effective credentials for this request. */
  credentials: boolean;
  /** Why the request is denied, if at all. */
  denied?: "origin" | "method" | "headers" | "pna";
  /** Status for denied requests. */
  denialStatus?: number;
}

/**
 * Reads a single header value, case-insensitively; array values take
 * the first entry. Real-world request objects (node `IncomingMessage`,
 * fetch `Headers`, Bun) expose lower-cased names, but plain-object
 * callers are free to use any casing.
 */
export function headerValue(
  headers: CorsRequestInput["headers"],
  name: string
): string | undefined {
  if (!headers) return undefined;
  const direct = headers[name];
  if (direct !== undefined) {
    if (typeof direct === "string") return direct;
    if (Array.isArray(direct) && direct.length > 0) return direct[0];
    return undefined;
  }
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      const value = headers[key];
      if (typeof value === "string") return value;
      if (Array.isArray(value) && value.length > 0) return value[0];
      return undefined;
    }
  }
  return undefined;
}

/** First-use casing of the incoming `Vary` header, if any. */
export function existingVary(headers: CorsRequestInput["headers"]): string[] | undefined {
  const value = headerValue(headers, HEADER_VARY);
  if (!value) return undefined;
  const tokens: string[] = [];
  for (const raw of value.split(",")) {
    const token = raw.trim();
    if (token) tokens.push(token);
  }
  return tokens.length > 0 ? tokens : undefined;
}

/**
 * Preserves existing `Vary` tokens while adding new ones (first-use
 * casing, case-insensitive dedupe) — servers should never be clobbered
 * and no duplicates are emitted.
 *
 * @param existing - Existing `Vary` tokens (first-use casing), if any.
 * @param additions - Canonical tokens to add.
 * @returns The merged token list in first-use casing.
 */
export function mergeVary(
  existing: string[] | undefined,
  additions: readonly string[]
): string[] {
  const merged = existing ? [...existing] : [];
  for (const token of additions) {
    const already = merged.some((t) => t.toLowerCase() === token.toLowerCase());
    if (!already) merged.push(token);
  }
  return merged;
}

/** Sorts a method list deterministically (common methods first, rest alphabetical). */
export function sortMethods(methods: readonly string[]): string[] {
  const order = ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS", "TRACE", "CONNECT"];
  const canonical: string[] = [];
  const rest: string[] = [];
  for (const method of methods) {
    const upper = method.toUpperCase();
    (order.includes(upper) ? canonical : rest).push(method);
  }
  canonical.sort((a, b) => order.indexOf(a.toUpperCase()) - order.indexOf(b.toUpperCase()));
  rest.sort((a, b) => a.localeCompare(b));
  return [...canonical, ...rest];
}

/** Sorts header names deterministically for stable, reproducible output. */
export function sortHeaderNames(names: string[]): string[] {
  return [...names].sort((a, b) => a.localeCompare(b) || a.length - b.length);
}

/** Case-insensitive subset check of requested vs. allowed headers. */
export function isHeaderSubset(requested: string[], allowed: string[]): boolean {
  const allowedLower = new Set(allowed.map((h) => h.toLowerCase()));
  return requested.every((h) => allowedLower.has(h.toLowerCase()));
}

/** Parses a CSV header into trimmed, deduplicated tokens. */
export function parseCsv(value: string | undefined): string[] {
  if (!value) return [];
  const seen = new Set<string>();
  const tokens: string[] = [];
  for (const raw of value.split(",")) {
    const token = raw.trim();
    if (token && !seen.has(token.toLowerCase())) {
      seen.add(token.toLowerCase());
      tokens.push(token);
    }
  }
  return tokens;
}

/**
 * Detects a CORS preflight per the configured mode.
 *
 * - `"auto"` — OPTIONS request carrying `Access-Control-Request-Method`
 * - `"always"` — every OPTIONS request (npm-`cors` compatibility)
 * - `"never"` — never (OPTIONS handled as a plain request)
 */
export function isPreflight(
  input: CorsRequestInput,
  mode: CorsPreflightMode
): boolean {
  const method = (input.method ?? "").toUpperCase();
  if (method !== "OPTIONS") return false;
  if (mode === "never") return false;
  if (mode === "always") return true;
  return headerValue(input.headers, HEADER_ACRM) !== undefined;
}

/** Structured origin resolution (per-origin credentials applied). */
export interface OriginResolution {
  allowed: boolean;
  /** Effective credentials flag for this request. */
  credentials: boolean;
  /** Origin string to reflect, when a callback resolved a concrete origin. */
  reflect?: string;
}

/** The complete, immutable engine. */
export interface CorsEngine {
  /** Resolves an origin against the compiled matcher. */
  resolveOrigin(rawOrigin: string | undefined): OriginResolution;
  /** Synchronous resolution (throws for callback-based origins). */
  process(input: CorsRequestInput): CorsResult;
  /** Async resolution supporting callback-based origins. */
  processAsync(input: CorsRequestInput): Promise<CorsResult>;
}

/**
 * Builds the immutable engine for a resolved configuration.
 *
 * @param config - Fully-resolved configuration (from `resolveConfig`).
 * @param matcher - Compiled origin matcher (from `compileOrigin`).
 * @returns The shared engine.
 */
export function createEngine(config: CorsConfig, matcher: CompiledOrigin): CorsEngine {
  const methodsHeader = sortMethods(config.methods ?? []).join(", ");

  const resolveOriginSync = (rawOrigin: string | undefined): OriginResolution => {
    if (rawOrigin === undefined) return { allowed: true, credentials: false };
    const match = resolveOrigin(matcher, rawOrigin);
    if (!match.matched) return { allowed: false, credentials: false };
    return { allowed: true, credentials: match.credentials ?? config.credentials ?? false };
  };

  /** Resolves the origin through a user callback (async path only). */
  const resolveOriginAsync = (rawOrigin: string | undefined): Promise<OriginResolution> =>
    new Promise<OriginResolution>((resolvePromise, reject) => {
      if (matcher.kind !== "callback") {
        resolvePromise(resolveOriginSync(rawOrigin));
        return;
      }
      matcher.callback(rawOrigin, (error, allow) => {
        if (error) {
          reject(error);
          return;
        }
        if (allow === false || allow === undefined || allow === null) {
          resolvePromise({ allowed: false, credentials: false });
        } else if (allow === true) {
          resolvePromise({
            allowed: true,
            credentials: config.credentials ?? false,
          });
        } else {
          resolvePromise({
            allowed: true,
            credentials: config.credentials ?? false,
            reflect: allow,
          });
        }
      });
    });

  /** Builds the block response when a request must not proceed. */
  const buildBlocked = (
    input: CorsRequestInput,
    preflight: boolean,
    state: ResolvedState
  ): CorsResult => {
    const respond =
      preflight ||
      state.denialStatus !== undefined ||
      config.failureStatus !== undefined;
    const headers: Record<string, string> = {};
    if (respond) {
      headers["Vary"] = mergeVary(
        existingVary(input.headers),
        preflight ? PREFLIGHT_VARY : ["Origin"]
      ).join(", ");
    }
    const statusCode = respond
      ? state.denialStatus ?? config.failureStatus ?? 403
      : undefined;
    return {
      allowed: false,
      blocked: true,
      preflight,
      statusCode,
      headers,
      origin: null,
    };
  };

  /** Emits the response headers for a permitted request. */
  const buildAllowed = (
    input: CorsRequestInput,
    preflight: boolean,
    state: ResolvedState
  ): CorsResult => {
    const headers: Record<string, string> = {};
    const origin = state.reflectOrigin ?? state.origin;

    if (origin !== undefined) {
      const reflect =
        origin === "*" || (matcher.kind === "any" && !state.credentials)
          ? state.credentials
            ? state.origin ?? "*"
            : "*"
          : origin;
      headers["Access-Control-Allow-Origin"] = reflect;
    }
    if (config.exposedHeaders !== undefined && config.exposedHeaders.length > 0) {
      headers["Access-Control-Expose-Headers"] = sortHeaderNames(config.exposedHeaders).join(", ");
    }
    if (state.credentials) {
      headers["Access-Control-Allow-Credentials"] = "true";
    }
    if (preflight) {
      headers["Access-Control-Allow-Methods"] = methodsHeader;
      const requestedHeaders = parseCsv(headerValue(input.headers, HEADER_ACRH));
      if (config.allowedHeaders === true) {
        if (requestedHeaders.length > 0) {
          headers["Access-Control-Allow-Headers"] = requestedHeaders.join(", ");
        }
      } else if (config.allowedHeaders !== undefined && config.allowedHeaders.length > 0) {
        headers["Access-Control-Allow-Headers"] = sortHeaderNames(config.allowedHeaders).join(", ");
      }
      if (
        headerValue(input.headers, HEADER_ACRPN)?.toLowerCase() === "true" &&
        config.allowPrivateNetwork
      ) {
        headers["Access-Control-Allow-Private-Network"] = "true";
      }
      headers["Access-Control-Max-Age"] = String(config.maxAge ?? 0);
    }

    const vary = mergeVary(
      existingVary(input.headers),
      preflight ? PREFLIGHT_VARY : ["Origin"]
    );
    headers["Vary"] = vary.join(", ");

    return {
      allowed: true,
      blocked: false,
      preflight,
      statusCode: preflight ? config.optionsSuccessStatus : undefined,
      headers,
      origin: origin === undefined ? null : origin,
    };
  };

  /** Common resolution pipeline shared by both paths. */
  const pipeline = (
    input: CorsRequestInput,
    preflight: boolean,
    state: ResolvedState
  ): CorsResult => {
    if (state.denied) {
      return buildBlocked(input, preflight, state);
    }
    if (!preflight) {
      return buildAllowed(input, false, state);
    }

    const requestedMethod = headerValue(input.headers, HEADER_ACRM);
    const hasRequestedMethod = requestedMethod !== undefined;
    const methodAllowed =
      hasRequestedMethod &&
      (config.methods ?? []).some((m) => m.toUpperCase() === requestedMethod.toUpperCase());
    if (hasRequestedMethod && !methodAllowed) {
      return buildBlocked(input, true, {
        ...state,
        denied: "method",
        denialStatus: config.failureStatus ?? 403,
      });
    }

    const requestedHeaders = parseCsv(headerValue(input.headers, HEADER_ACRH));
    if (
      hasRequestedMethod &&
      config.allowedHeaders !== undefined &&
      config.allowedHeaders !== true &&
      !isHeaderSubset(requestedHeaders, config.allowedHeaders)
    ) {
      return buildBlocked(input, true, {
        ...state,
        denied: "headers",
        denialStatus: config.failureStatus ?? 403,
      });
    }

    if (
      headerValue(input.headers, HEADER_ACRPN)?.toLowerCase() === "true" &&
      !config.allowPrivateNetwork
    ) {
      return buildBlocked(input, true, {
        ...state,
        denied: "pna",
        denialStatus: config.failureStatus ?? 403,
      });
    }

    const result = buildAllowed(input, true, state);
    config.onPreflight?.({ origin: state.origin ?? null, request: input, result });
    return result;
  };

  const process = (input: CorsRequestInput): CorsResult => {
    const origin = input.origin ?? headerValue(input.headers, HEADER_ORIGIN);
    const preflight = isPreflight(input, config.preflight ?? "auto");

    let state: ResolvedState;
    if (origin === undefined) {
      state = { origin: undefined, credentials: false };
    } else {
      const resolution = resolveOriginSync(origin);
      state = {
        origin,
        credentials: resolution.credentials,
        denied: resolution.allowed ? undefined : "origin",
      };
    }

    const result = pipeline(input, preflight, state);
    if (result.blocked && state.origin !== undefined) {
      config.onBlock?.({ origin: state.origin, request: input });
    }
    return result;
  };

  const processAsync = async (input: CorsRequestInput): Promise<CorsResult> => {
    const origin = input.origin ?? headerValue(input.headers, HEADER_ORIGIN);
    const preflight = isPreflight(input, config.preflight ?? "auto");

    let state: ResolvedState;
    if (origin === undefined) {
      state = { origin: undefined, credentials: false };
    } else if (matcher.kind !== "callback") {
      const resolution = resolveOriginSync(origin);
      state = {
        origin,
        credentials: resolution.credentials,
        denied: resolution.allowed ? undefined : "origin",
      };
    } else {
      const resolution = await resolveOriginAsync(origin);
      state = {
        origin,
        reflectOrigin: resolution.reflect,
        credentials: resolution.credentials,
        denied: resolution.allowed ? undefined : "origin",
      };
    }

    const result = pipeline(input, preflight, state);
    if (result.blocked && state.origin !== undefined) {
      config.onBlock?.({ origin: state.origin, request: input });
    }
    return result;
  };

  return {
    resolveOrigin: resolveOriginSync,
    process,
    processAsync,
  };
}