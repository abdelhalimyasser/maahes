/**
 * @fileoverview The pure CSP engine: config + context → policy.
 *
 * No framework types, no I/O, no side effects. Given a resolved
 * configuration and an optional context (a per-request nonce) it
 * produces a deterministic header plan — directives sorted by name,
 * sources in their configured order (order is meaningful in CSP 3
 * precedence rules).
 *
 * Determinism contract: the same configuration and context ALWAYS
 * produce the same policy — safe to snapshot, cache and test.
 *
 * Injection safety: directive names are RFC 7230 tokens; source values
 * reject control characters, `;`, `,` and `"` at validation time —
 * directive and policy injection is impossible by construction.
 *
 * @module csp/core
 */

import { CspOptionsError } from "./errors";
import type { CspBuildContext, CspParsed, CspPlan } from "./types";
import type { ResolvedCspConfig } from "./config";

/** RFC 7230 token — valid directive name characters. */
const DIRECTIVE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** Control characters forbidden in source values (tab excluded: not allowed in CSP either). */
const FORBIDDEN_SOURCE_CHARS = /[\u0000-\u001F\u007F;,"]/;
/** The `'nonce-$nonce'` template — the ONLY legal placeholders. */
const NONCE_TEMPLATE_RE = /^'nonce-\$nonce'$/;
/** Valid nonce characters (CSP Level 3 base64-value grammar). */
const NONCE_VALUE_RE = /^[A-Za-z0-9+/=_-]+$/;

/** Policy header names emitted by this module. */
export const CSP_HEADER = "Content-Security-Policy";
export const CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

/**
 * Serializes a directive map into a canonical policy string.
 * Deterministic: directive names sorted with `localeCompare`, sources in
 * configured order, joined with single spaces, directives with `; `.
 *
 * @param directives - Directive name → ordered sources.
 * @returns The serialized policy (no trailing `;`).
 */
export function serializeCsp(directives: Record<string, string[]>): string {
  const names = Object.keys(directives).sort((a, b) => a.localeCompare(b));
  return names
    .map((name) => {
      const sources = directives[name];
      return sources.length === 0 ? name : `${name} ${sources.join(" ")}`;
    })
    .join("; ");
}

/**
 * Strictly parses and validates a CSP policy string into a directive
 * map. Directive names are lowercased; sources keep their order.
 *
 * Strictness is deliberate: a policy that would inject or confuse is
 * rejected with `CspOptionsError` instead of being emitted.
 *
 * @param policy - A single CSP policy (multiple comma-separated policies
 *   are rejected — this module emits one policy per header).
 * @returns The parsed directives.
 * @throws {CspOptionsError} On malformed or hostile policy strings.
 */
export function parseCsp(policy: string): CspParsed {
  if (typeof policy !== "string" || policy.trim() === "") {
    throw new CspOptionsError("csp.policy must be a non-empty string.");
  }
  if (policy.includes(",")) {
    throw new CspOptionsError("csp.policy must be a single policy (commas separate policies, which are not supported).");
  }

  const directives: Record<string, string[]> = {};
  for (const rawDirective of policy.split(";")) {
    const trimmed = rawDirective.trim();
    if (trimmed === "") continue;

    const parts = trimmed.split(/\s+/);
    const name = parts[0].toLowerCase();
    if (!DIRECTIVE_NAME_RE.test(name)) {
      throw new CspOptionsError(`csp.policy contains an invalid directive name (got ${JSON.stringify(name)}).`);
    }
    if (name in directives) {
      throw new CspOptionsError(`csp.policy contains directive "${name}" more than once.`);
    }

    const sources = parts.slice(1);
    for (const source of sources) {
      validateSource(name, source);
    }
    if (sources.includes("'none'") && sources.length > 1) {
      throw new CspOptionsError(`csp.${name} may only contain 'none' as its sole source.`);
    }
    directives[name] = sources;
  }

  if (Object.keys(directives).length === 0) {
    throw new CspOptionsError("csp.policy contains no directives.");
  }
  return { directives };
}

/**
 * Validates a single source expression. Called at construction (config)
 * and at parse time (external policy strings).
 *
 * @param directive - Directive name (for error messages).
 * @param source - The source expression to validate.
 * @throws {CspOptionsError} When the source is invalid.
 */
export function validateSource(directive: string, source: string): void {
  if (typeof source !== "string" || source === "") {
    throw new CspOptionsError(`csp.${directive} contains an empty source.`);
  }
  if (FORBIDDEN_SOURCE_CHARS.test(source)) {
    throw new CspOptionsError(
      `csp.${directive} source must not contain control characters, ";", "," or '"' (got ${JSON.stringify(source)}).`
    );
  }
  if (source.includes("$nonce") && !NONCE_TEMPLATE_RE.test(source)) {
    throw new CspOptionsError(
      `csp.${directive} may only use a nonce through the 'nonce-$nonce' template (got ${JSON.stringify(source)}).`
    );
  }
}

/**
 * Builds the deterministic CSP header plan for a configuration and
 * context.
 *
 * @param config - Fully-resolved, validated configuration.
 * @param context - Per-request nonce (required by `'nonce-$nonce'`
 *   templates).
 * @returns The plan: one header, `Content-Security-Policy` or
 *   `Content-Security-Policy-Report-Only`.
 * @throws {CspOptionsError} When a nonce template is used without a
 *   valid nonce in the context.
 */
export function buildCsp(config: ResolvedCspConfig, context: CspBuildContext = {}): CspPlan {
  const directives: Record<string, string[]> = {};
  for (const [name, sources] of Object.entries(config.directives)) {
    directives[name] = sources.map((source) => {
      if (source.includes("$nonce")) {
        const nonce = context.nonce;
        if (nonce === undefined || !NONCE_VALUE_RE.test(nonce)) {
          throw new CspOptionsError(
            `csp.${name} uses a 'nonce-$nonce' template: build() requires a valid context.nonce (got ${JSON.stringify(nonce)}).`
          );
        }
        return source.replace("$nonce", nonce);
      }
      return source;
    });
  }

  const policy = serializeCsp(directives);
  const header = config.reportOnly ? CSP_REPORT_ONLY_HEADER : CSP_HEADER;
  return { headers: { [header]: policy } };
}