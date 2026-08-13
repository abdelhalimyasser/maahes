/**
 * @fileoverview Type definitions for the Maahes CORS module.
 *
 * A framework-agnostic CORS engine: configure once, then consume through
 * a pure header processor, a Connect/Express-style middleware, a raw
 * `node:http` handler or a Web-standard fetch wrapper (Bun, Node ≥ 18,
 * edge runtimes). Built-in extras beyond typical CORS packages:
 * glob-based origin allowlists, per-origin credentials, credentials-safe
 * header reflection, Private Network Access support and Vary-correct
 * responses.
 *
 * @module cors/types
 * @packageDocumentation
 */

/** When the module responds to OPTIONS requests. */
export type CorsPreflightMode = "auto" | "always" | "never";

/** How string origin patterns are interpreted. */
export type CorsMatchMode = "exact" | "glob" | "regex" | "auto";

/**
 * A single origin rule that may fine-tune credentials for one origin.
 * `credentials` overrides the global {@link CorsConfig.credentials} flag
 * for matching origins.
 */
export interface CorsOriginRule {
  /** Origin pattern: exact string, glob (e.g. `https://*.example.com`) or RegExp. */
  pattern: string | RegExp;
  /** Per-origin credentials override; falls back to the global flag when unset. */
  credentials?: boolean;
}

/**
 * Origin resolution callback, API-compatible with the popular `cors`
 * package: `(origin, callback)` — callback with `(err, allow)` where
 * `allow` is a boolean or the origin string to reflect.
 */
export type CorsOriginCallback = (
  origin: string | undefined,
  callback: (error: Error | null, allow?: string | boolean) => void
) => void;

/** Headers shape accepted by the engine; values may be arrays. */
export type CorsHeadersInput = Record<string, string | string[] | undefined>;

/** A request description consumed by the pure engine. */
export interface CorsRequestInput {
  /** HTTP method, e.g. `"OPTIONS"`. */
  method?: string;
  /** Raw headers (case-insensitive names); array values take the first entry. */
  headers?: CorsHeadersInput;
  /** Explicit origin, bypassing the `Origin` header (programmatic convenience). */
  origin?: string;
}

/** Structured result of the CORS engine for one request. */
export interface CorsResult {
  /** Whether the request is permitted to proceed. */
  allowed: boolean;
  /** `true` when an explicit origin was denied (vs. a request without Origin). */
  blocked: boolean;
  /** `true` when the request was treated as a CORS preflight. */
  preflight: boolean;
  /** Status the caller should respond with (preflight / hard block), if any. */
  statusCode?: number;
  /** Headers to set on the response (includes merged `Vary`). */
  headers: Record<string, string>;
  /** The resolved `Access-Control-Allow-Origin` value, if any. */
  origin: string | null;
}

/** Everything reported to the `onBlock` hook. */
export interface CorsBlockContext {
  /** The denied origin, or `null`/undefined when absent. */
  origin: string | null;
  /** The request that triggered the block. */
  request: CorsRequestInput;
}

/** Everything reported to the `onPreflight` hook. */
export interface CorsPreflightContext {
  origin: string | null;
  request: CorsRequestInput;
  result: CorsResult;
}

/** Handler context bag passed to middleware. */
export interface CorsRequestLike {
  method?: string;
  headers?: CorsHeadersInput;
}

/**
 * Configuration accepted by the {@link Cors} factory. Every field is
 * optional and falls back to {@link DEFAULT_CORS_CONFIG}; a deep merge
 * keeps unset fields at their defaults (same contract as the Password
 * module).
 */
export interface CorsConfig {
  /**
   * Allowed origins.
   * - `"*"` — any origin (default)
   * - `string[]` — exact origins and/or glob patterns (`"https://*.example.com"`)
   * - `RegExp` — matched against the full origin
   * - `CorsOriginRule[]` — per-origin entries with optional credentials override
   * - `CorsOriginCallback` — dynamic resolver `(origin, cb)`; requires `processAsync`
   */
  origin?: string | string[] | RegExp | CorsOriginRule[] | CorsOriginCallback;
  /**
   * Convenience alias for string/rule origin lists; merged with `origin`
   * when both are provided.
   */
  allowlist?: Array<string | CorsOriginRule>;
  /**
   * How string patterns are interpreted: `"exact"`, `"glob"` (uses `*`
   * and `?` wildcards), `"regex"` (strings are RegExp sources), or
   * `"auto"` (wildcards present → glob, otherwise exact). Default `"auto"`.
   */
  matchMode?: CorsMatchMode;
  /** Allowed methods for preflights. Default `GET,HEAD,PUT,PATCH,POST,DELETE`. */
  methods?: string[];
  /**
   * Allowed request headers for preflights. `true` reflects the
   * browser's requested headers (the credentials-safe wildcard). When a
   * string array, the request's headers must be a subset (case-insensitive).
   * Default: reflect.
   */
  allowedHeaders?: string[] | true;
  /** Headers exposed to browser JavaScript via `Access-Control-Expose-Headers`. Default `[]`. */
  exposedHeaders?: string[];
  /**
   * Whether cookies/credentials may be sent. When `true`, credentials
   * are gated per-origin if origin rules carry their own `credentials`
   * flag. Default `false` (secure baseline).
   */
  credentials?: boolean;
  /** Preflight cache lifetime in seconds (`Access-Control-Max-Age`). Default `86400`. */
  maxAge?: number;
  /**
   * Preflight response policy: `"auto"` (only respond to genuine
   * preflights carrying `Access-Control-Request-Method`), `"always"`
   * (respond to every OPTIONS — npm-`cors` behavior), `"never"`.
   * Default `"auto"`.
   */
  preflight?: CorsPreflightMode;
  /** Status for successful preflight responses. Default `204`. */
  optionsSuccessStatus?: number;
  /**
   * Private Network Access support: when a preflight declares
   * `Access-Control-Request-Private-Network: true`, the request is
   * denied unless this option is enabled (which answers with
   * `Access-Control-Allow-Private-Network: true`). Default `false`.
   */
  allowPrivateNetwork?: boolean;
  /** Accept the literal `"null"` origin (sandboxed iframes, `file://`). Default `false`. */
  allowNullOrigin?: boolean;
  /**
   * When set, denied requests receive this HTTP status (hard block) and
   * the `onBlock` hook fires. When unset (default), CORS headers are
   * simply omitted and the browser performs the blocking.
   */
  failureStatus?: number;
  /** Called whenever an explicit origin is denied (logging / abuse detection). */
  onBlock?: (context: CorsBlockContext) => void;
  /** Called after a successful preflight resolution (analytics / audits). */
  onPreflight?: (context: CorsPreflightContext) => void;
  /**
   * Behavior preset: `"default"` (secure, `preflight: "auto"`) or
   * `"express"` (compat with the npm `cors` package: answer every
   * OPTIONS, reflect requested headers). Preset fields can still be
   * overridden explicitly.
   */
  preset?: "default" | "express";
}

/**
 * The immutable, share-safe public API created by the {@link Cors}
 * factory. All structured inputs/outputs work with any framework.
 */
export interface CorsModule {
  /**
   * Pure, synchronous CORS resolution: never touches I/O. Throws when
   * the config uses a callback-based origin (use {@link processAsync}).
   */
  process(input: CorsRequestInput): CorsResult;
  /** Async variant supporting callback-based origin resolvers. */
  processAsync(input: CorsRequestInput): Promise<CorsResult>;
  /**
   * Connect/Express-style middleware `(req, res, next)`. When `next` is
   * omitted it behaves as a raw `node:http` request handler (it ends
   * preflight/blocked responses; simple requests are decorated only).
   */
  middleware(): CorsMiddleware;
  /**
   * Web-standard wrapper. With `handler`, decorates its Response with
   * CORS headers (and answers preflights). Without it, acts as a
   * CORS-only adapter: answers preflights, returns `undefined` otherwise.
   * Works on Node ≥ 18, Bun and edge runtimes.
   */
  fetchHandler(
    handler?: (request: Request) => Response | Promise<Response>
  ): (request: Request) => Promise<Response | undefined>;
  /** `true` when the input is a genuine CORS preflight (OPTIONS + `Access-Control-Request-Method`). */
  isPreflight(input: CorsRequestInput): boolean;
  /** Resolves an origin against the configuration; `null` when denied. */
  allowedOrigin(origin: string | undefined): string | null;
}

/** Minimal structural shapes accepted by the middleware. */
export interface IncomingMessageLike {
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
}
export interface ServerResponseLike {
  setHeader(name: string, value: string): unknown;
  statusCode: number;
  end(): unknown;
}
export type CorsNextCallback = () => void;

export type CorsMiddleware = (
  req: IncomingMessageLike,
  res: ServerResponseLike,
  next?: CorsNextCallback
) => void;