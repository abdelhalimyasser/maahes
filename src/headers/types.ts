/**
 * @fileoverview Type definitions for the Maahes security headers module.
 *
 * A deterministic, framework-agnostic HTTP security header engine:
 * configure once, consume through a pure builder, a Web `Headers` view,
 * a Connect/Express-style middleware or a Web-standard fetch wrapper.
 *
 * Scope and non-goals:
 * - This module NEVER emits `Content-Security-Policy`. CSP is a
 *   dedicated future module (`src/csp/`) with its own policy grammar;
 *   this engine only reserves its position in the emission order.
 * - Security headers are defense-in-depth, NOT a security boundary:
 *   they mitigate classes of browser-side attacks but never replace
 *   application-level checks, authentication or authorization.
 * - Header removal never guarantees fingerprinting protection —
 *   upstream infrastructure (proxies, frameworks) may re-add headers.
 *
 * @module headers/types
 * @packageDocumentation
 */

/** Built-in behavior presets (see {@link PRESETS}). */
export type SecurityHeadersPreset = "minimal" | "default" | "strict";

/** HSTS configuration. `false` disables the header entirely. */
export interface HstsConfig {
  /** Lifetime in seconds. Must be a non-negative integer. */
  maxAge: number;
  /** Apply to all subdomains. */
  includeSubDomains: boolean;
  /**
   * Request inclusion in the browser preload lists. Never enabled by
   * default: it is a permanent commitment for the whole domain. Requires
   * `maxAge >= 31536000` and `includeSubDomains: true` (fail fast).
   */
  preload: boolean;
}

/** Values for `X-Frame-Options`; `false` disables the header. */
export type FrameOptionsValue = "DENY" | "SAMEORIGIN";

/**
 * Values for `Cross-Origin-Opener-Policy`. `same-origin` isolates the
 * browsing context from cross-origin popups (and vice versa) — it can
 * break OAuth popup flows and cross-origin `window.opener` access.
 */
export type CoopValue = "same-origin" | "same-origin-allow-popups" | "unsafe-none";

/**
 * Values for `Cross-Origin-Embedder-Policy`. `credentialless` (default)
 * keeps most third-party resources working while dropping credentials;
 * `require-corp` requires every subresource to carry CORS/CORP headers.
 */
export type CoepValue = "require-corp" | "credentialless" | "unsafe-none";

/**
 * Values for `Cross-Origin-Resource-Policy`. Only meaningful on
 * resources YOU serve; `same-origin` blocks embedding by other sites
 * and can break legitimate cross-origin consumers.
 */
export type CorpValue = "same-origin" | "same-site" | "cross-origin";

/**
 * Values for `X-XSS-Protection` (legacy browser filter). Deliberately a
 * typed union, never an ambiguous boolean: `"0"` disables the legacy
 * filter (the default — CSP is the modern control), `"1"` / `"1; mode=block"`
 * opt back into a filter with known bypasses.
 */
export type XssProtectionValue = "0" | "1" | "1; mode=block";

/** Values for `X-Permitted-Cross-Domain-Policies` (legacy Flash/PDF policy). */
export type CrossDomainPolicyValue = "none" | "master-only" | "by-content-type" | "all";

/**
 * Allowed `Referrer-Policy` values (per the WHATWG specification).
 */
export type ReferrerPolicyValue =
  | "no-referrer"
  | "no-referrer-when-downgrade"
  | "origin"
  | "origin-when-cross-origin"
  | "same-origin"
  | "strict-origin"
  | "strict-origin-when-cross-origin"
  | "unsafe-url";

/**
 * Configuration accepted by the {@link SecurityHeaders} factory. Every
 * field is optional; omitted values fall back to the defaults of the
 * selected preset. A header is disabled with `false` (or `false`/`0`
 * where the type allows), never by omission.
 */
export interface SecurityHeadersConfig {
  /** Behavior preset. Default `"default"`. */
  preset?: SecurityHeadersPreset;
  /**
   * When `true` (default), `Strict-Transport-Security` is emitted ONLY
   * in secure contexts. Adapters detect security from the request
   * (TLS socket / `https://` URL); `build()` assumes secure unless the
   * context says otherwise.
   */
  httpsOnly?: boolean;
  /**
   * When `true` (default), Maahes headers replace any same-named header
   * already present on the response. When `false`, existing application
   * headers win and Maahes skips them.
   */
  overwrite?: boolean;
  /**
   * Response headers to remove, matched case-insensitively. Removal is
   * deterministic and always applied (regardless of `overwrite`).
   * NOTE: upstream infrastructure may re-add these headers; removal is
   * not a fingerprinting guarantee.
   */
  remove?: string[];
  /**
   * Additional headers to emit, sorted deterministically. An escape
   * hatch: values are NOT treated as security policy — the caller owns
   * their semantics. Names and values are validated at construction
   * (RFC 7230 token names; no CR/LF/NUL — response splitting is
   * impossible).
   */
  extra?: Record<string, string>;
  /** `X-Content-Type-Options: nosniff`. Default `true`. */
  nosniff?: boolean;
  /** `X-Frame-Options`. Default `"DENY"`. `false` disables. */
  frameOptions?: FrameOptionsValue | false;
  /** `Referrer-Policy`. Default `"strict-origin-when-cross-origin"`. `false` disables. */
  referrerPolicy?: ReferrerPolicyValue | false;
  /** `Strict-Transport-Security`. Default `{ maxAge: 31536000, includeSubDomains: true, preload: false }`. */
  hsts?: Partial<HstsConfig> | false;
  /** `Cross-Origin-Opener-Policy`. Default `"same-origin"`. `false` disables. */
  coop?: CoopValue | false;
  /** `Cross-Origin-Embedder-Policy`. Default `"credentialless"`. `false` disables. */
  coep?: CoepValue | false;
  /**
   * `Cross-Origin-Resource-Policy`. Default `false` (disabled) for
   * compatibility; the `strict` preset enables `"same-origin"`. Enabling
   * it on resources shared cross-origin breaks those consumers.
   */
  corp?: CorpValue | false;
  /**
   * `Permissions-Policy` (modern, conservative default). Accepts any
   * valid policy string, e.g. `"camera=(), microphone=(), geolocation=()"`.
   * `false` disables.
   */
  permissionsPolicy?: string | false;
  /**
   * `X-XSS-Protection` (legacy browser filter). Default `"0"` — the
   * legacy filter is disabled because CSP is the modern XSS control.
   */
  xssProtection?: XssProtectionValue | false;
  /** `X-Permitted-Cross-Domain-Policies` (legacy Flash/PDF hardening). Default `"none"` in default/strict presets. */
  crossDomainPolicy?: CrossDomainPolicyValue | false;
  /** `X-DNS-Prefetch-Control: off` — optional hardening for HTML pages. Default `false`. */
  dnsPrefetchControl?: boolean;
  /** `Origin-Agent-Cluster: ?1` — optional hardening. Default `false`. */
  originAgentCluster?: boolean;
}

/**
 * Context evaluated when building a header set. Supplying `existing`
 * lets the engine honor `overwrite` and `remove`; supplying `secure`
 * gates HSTS emission when `httpsOnly` is enabled.
 */
export interface HeaderBuildContext {
  /** `true` when the response will travel over HTTPS. Assumed `true` when omitted. */
  secure?: boolean;
  /** Headers already present on the response (any casing). */
  existing?:
    | Record<string, string | string[] | undefined>
    | Headers
    | ReadonlyArray<readonly [string, string]>;
}

/**
 * The deterministic result of {@link SecurityHeadersModule.build}:
 * headers to set (existing kept, then known headers in fixed order,
 * then extras sorted) plus headers to remove.
 */
export interface HeaderPlan {
  /** Headers to set, in emission order (deterministic for equal inputs). */
  headers: Record<string, string>;
  /** Header names to remove, case-insensitively, in input order. */
  removed: string[];
}

/**
 * The immutable, share-safe public API created by the {@link SecurityHeaders}
 * factory.
 */
export interface SecurityHeadersModule {
  /**
   * Pure, deterministic header resolution: no I/O, no framework types.
   * Same config + context always produce the same plan.
   */
  build(context?: HeaderBuildContext): HeaderPlan;
  /** Web-standard `Headers` view of {@link build} (Bun, Node ≥ 18, edge). */
  headers(context?: HeaderBuildContext): Headers;
  /**
   * Connect/Express-style middleware `(req, res, next)`. Decorates the
   * response, always calls `next()`, never ends the request and never
   * swallows downstream errors.
   */
  middleware(): SecurityHeadersMiddleware;
  /**
   * Web-standard fetch wrapper. Decorates the wrapped handler's
   * `Response` with the header set (honoring `overwrite`/`remove`),
   * preserving status, statusText and body. Secure context is derived
   * from the request URL.
   */
  fetchHandler(
    handler: (request: Request) => Response | Promise<Response>
  ): (request: Request) => Promise<Response>;
}

/** Minimal structural shapes accepted by the middleware. */
export interface HeadersRequestLike {
  /** Express sets `secure` from the `trust proxy` setting. */
  secure?: boolean;
  socket?: { encrypted?: boolean };
}
export interface HeadersResponseLike {
  setHeader(name: string, value: string): unknown;
  removeHeader?(name: string): unknown;
  getHeaders?(): Record<string, string | string[] | undefined>;
}
export type SecurityHeadersNextCallback = (error?: unknown) => void;

export type SecurityHeadersMiddleware = (
  req: HeadersRequestLike,
  res: HeadersResponseLike,
  next?: SecurityHeadersNextCallback
) => void;