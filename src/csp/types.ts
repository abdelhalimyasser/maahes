/**
 * @fileoverview Type definitions for the Maahes CSP module.
 *
 * A deterministic Content Security Policy engine: configure directives
 * once, build a policy string per request context (nonce-aware), and
 * attach it to responses — or plug a static policy straight into the
 * `SecurityHeaders` module (`csp` option), which emits it first in its
 * canonical header order.
 *
 * Grammar notes:
 * - Directive names are validated as RFC 7230 tokens and normalized to
 *   lowercase; unknown directive names are accepted (future-proof),
 *   hostile input is not.
 * - Source values are validated at construction: no control characters,
 *   no `;` / `,` / `"` — directive and policy injection is impossible.
 * - `'none'` is only valid as a directive's sole value (CSP grammar).
 * - A `'nonce-$nonce'` template marks a directive to receive the
 *   per-request nonce from the build context. Building without a nonce
 *   throws `CspOptionsError` — fail loud, never emit a broken policy.
 *
 * @module csp/types
 * @packageDocumentation
 */

/** Built-in policy presets (see {@link PRESETS}). */
export type CspPreset = "minimal" | "default" | "strict";

/**
 * A single CSP source expression: keywords (`'self'`, `'none'`,
 * `'strict-dynamic'`, …), schemes (`https:`), hosts (`https://example.com`),
 * wildcards (`*.example.com`), hashes (`'sha256-…'`), nonces
 * (`'nonce-abc123'`), or the `'nonce-$nonce'` template (replaced from
 * the build context at build time).
 */
export type CspSource = string;

/**
 * Directive map accepted by the factory. Keys are directive names
 * (case-insensitive, normalized to lowercase); values are source
 * expressions in their intended order (order is meaningful in CSP 3
 * precedence rules). A single string is shorthand for a one-source
 * directive.
 */
export type CspDirectives = Record<string, CspSource[] | CspSource>;

/**
 * Configuration accepted by the {@link Csp} factory. Every field is
 * optional; omitted fields fall back to the defaults of the selected
 * preset.
 */
export interface CspConfig {
  /** Behavior preset. Default `"default"`. */
  preset?: CspPreset;
  /**
   * Directives to emit, merged over the preset's directives (per
   * directive name: user values replace preset values).
   */
  directives?: CspDirectives;
  /**
   * When `true`, emit `Content-Security-Policy-Report-Only` instead of
   * `Content-Security-Policy`. Use alongside a normal policy to observe
   * violations before enforcing. Default `false`.
   */
  reportOnly?: boolean;
}

/**
 * Context evaluated when building a policy. Currently carries the
 * per-request nonce required by `'nonce-$nonce'` templates.
 */
export interface CspBuildContext {
  /**
   * Per-request nonce (CSP Level 3, base64-ish value). Required when
   * any directive uses the `'nonce-$nonce'` template; the resulting
   * policy embeds `'nonce-<value>'`. Must be non-empty and contain
   * only `[A-Za-z0-9+/=_-]`.
   */
  nonce?: string;
}

/**
 * The deterministic result of {@link CspModule.build}: the headers to
 * set on the response. Mirrors the `SecurityHeaders` `HeaderPlan`
 * shape (minus removals — CSP never removes headers).
 */
export interface CspPlan {
  /** Headers to set: `Content-Security-Policy` (or `-Report-Only`). */
  headers: Record<string, string>;
}

/**
 * The parsed form of a CSP policy string: directive names (lowercase)
 * to ordered source lists.
 */
export interface CspParsed {
  directives: Record<string, string[]>;
}

/**
 * The immutable, share-safe public API created by the {@link Csp}
 * factory.
 */
export interface CspModule {
  /**
   * Pure, deterministic policy resolution: no I/O, no framework types.
   * Same config + context always produce the same headers.
   */
  build(context?: CspBuildContext): CspPlan;
  /** Web-standard `Headers` view of {@link build} (Bun, Node ≥ 18, edge). */
  headers(context?: CspBuildContext): Headers;
  /** The serialized policy string (directives sorted; no trailing `;`). */
  policy(context?: CspBuildContext): string;
  /** Strictly parses and validates an existing policy string. */
  parse(policy: string): CspParsed;
}