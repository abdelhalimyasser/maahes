/**
 * @fileoverview The pure security headers engine: config + context → plan.
 *
 * No framework types, no I/O, no side effects. Given a resolved
 * configuration and an optional context (secure flag + existing
 * response headers) it produces a deterministic {@link HeaderPlan}:
 * existing headers (minus removals/overwrites), then the known security
 * headers in a fixed order, then user extras sorted by name.
 *
 * Determinism contract: the same configuration and context ALWAYS
 * produce the same plan — safe to snapshot, cache and test.
 *
 * CSP NOTE: `Content-Security-Policy` is only emitted when the
 * configuration explicitly provides one (`headers.csp`), resolved via
 * the dedicated `src/csp/` module. Position 1 in the emission order is
 * reserved for it; without a policy, no CSP header is produced.
 *
 * @module headers/core
 */

import type { HeaderBuildContext, HeaderPlan } from "./types";
import type { ResolvedSecurityHeadersConfig } from "./config";

/** Canonical emission order of the known security headers. */
export const KNOWN_HEADER_ORDER = [
  "Content-Security-Policy",
  "Content-Security-Policy-Report-Only",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Embedder-Policy",
  "Cross-Origin-Resource-Policy",
  "Permissions-Policy",
  "X-XSS-Protection",
  "X-Permitted-Cross-Domain-Policies",
  "X-DNS-Prefetch-Control",
  "Origin-Agent-Cluster",
] as const;

/** Normalized internal representation of an existing header entry. */
type ExistingEntry = { name: string; value: string };

/**
 * Normalizes any supported `existing` input into ordered entries.
 * Header names keep their original casing; array values take the first
 * entry (documented, deterministic — mirrors the CORS engine).
 *
 * @param existing - Raw existing headers (Record, `Headers` or entries).
 * @returns Ordered existing entries.
 */
export function normalizeExisting(
  existing: HeaderBuildContext["existing"]
): ExistingEntry[] {
  if (!existing) return [];

  const entries: ExistingEntry[] = [];

  if (existing instanceof Headers) {
    existing.forEach((value, name) => entries.push({ name, value }));
    return entries;
  }

  if (Array.isArray(existing)) {
    for (const [name, value] of existing) {
      entries.push({ name, value });
    }
    return entries;
  }

  for (const [name, value] of Object.entries(existing)) {
    if (value === undefined) continue;
    entries.push({ name, value: Array.isArray(value) ? (value[0] ?? "") : value });
  }
  return entries;
}

/**
 * Builds the deterministic header plan for a configuration and context.
 *
 * Order of operations:
 * 1. start from the existing headers (input order, original casing),
 * 2. drop entries whose name matches `config.remove` (case-insensitive),
 * 3. emit the known security headers in {@link KNOWN_HEADER_ORDER} —
 *    when `overwrite` is `false`, existing same-named headers win and
 *    ours are skipped; when `true`, ours replace them (no duplicates),
 * 4. append `config.extra` sorted by name, honoring `overwrite` the
 *    same way,
 * 5. `Strict-Transport-Security` is emitted only when the context is
 *    secure and `httpsOnly` is disabled, or the context says secure.
 *
 * @param config - Fully-resolved, validated configuration.
 * @param context - Secure flag and/or existing response headers.
 * @returns The deterministic plan (headers in emission order + removals).
 */
export function buildHeaderSet(
  config: ResolvedSecurityHeadersConfig,
  context: HeaderBuildContext = {}
): HeaderPlan {
  const secure = context.secure ?? true;
  const existing = normalizeExisting(context.existing);

  const removedLower = new Set(config.remove.map((name) => name.toLowerCase()));

  let kept = existing.filter((entry) => !removedLower.has(entry.name.toLowerCase()));
  const result: Record<string, string> = {};
  for (const entry of kept) result[entry.name] = entry.value;

  /** Applies overwrite semantics and prevents duplicate names. */
  const emit = (name: string, value: string): void => {
    const lower = name.toLowerCase();
    if (!config.overwrite && kept.some((entry) => entry.name.toLowerCase() === lower)) {
      return; // existing application header wins
    }
    if (config.overwrite) {
      // Replace any existing same-named entry so no duplicates are emitted.
      kept = kept.filter((entry) => entry.name.toLowerCase() !== lower);
      for (const key of Object.keys(result)) {
        if (key.toLowerCase() === lower) delete result[key];
      }
    }
    result[name] = value;
  };

    if (config.csp) {
    emit(
      config.csp.reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy",
      config.csp.policy
    );
  }

  const hstsEmitted = config.hsts !== false && (config.httpsOnly === false || secure);
  if (hstsEmitted && config.hsts) {
    const hsts = config.hsts;
    let value = `max-age=${hsts.maxAge}`;
    if (hsts.includeSubDomains) value += "; includeSubDomains";
    if (hsts.preload) value += "; preload";
    emit("Strict-Transport-Security", value);
  }

  if (config.nosniff) emit("X-Content-Type-Options", "nosniff");
  if (config.frameOptions) emit("X-Frame-Options", config.frameOptions);
  if (config.referrerPolicy) emit("Referrer-Policy", config.referrerPolicy);
  if (config.coop) emit("Cross-Origin-Opener-Policy", config.coop);
  if (config.coep) emit("Cross-Origin-Embedder-Policy", config.coep);
  if (config.corp) emit("Cross-Origin-Resource-Policy", config.corp);
  if (config.permissionsPolicy) emit("Permissions-Policy", config.permissionsPolicy);
  if (config.xssProtection) emit("X-XSS-Protection", config.xssProtection);
  if (config.crossDomainPolicy) emit("X-Permitted-Cross-Domain-Policies", config.crossDomainPolicy);
  if (config.dnsPrefetchControl) emit("X-DNS-Prefetch-Control", "off");
  if (config.originAgentCluster) emit("Origin-Agent-Cluster", "?1");

  const extraNames = Object.keys(config.extra).sort((a, b) => a.localeCompare(b));
  for (const name of extraNames) {
    emit(name, config.extra[name]);
  }

  return { headers: result, removed: [...config.remove] };
}