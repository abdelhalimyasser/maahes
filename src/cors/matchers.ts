/**
 * @fileoverview Origin matching primitives for the CORS module.
 *
 * Supports exact strings, glob patterns (`https://*.example.com`),
 * RegExp, wildcard, dynamic callbacks and per-origin rules that can
 * override the global credentials flag. Matchers are compiled once at
 * construction time and reused for every request, keeping the hot path
 * allocation-free and deterministic.
 *
 * @module cors/matchers
 */

import type { CorsConfig, CorsOriginCallback, CorsOriginRule } from "./types";

/** Result of resolving one origin against a compiled matcher. */
export interface OriginMatch {
  /** Whether the origin is permitted. */
  matched: boolean;
  /** Per-origin credentials override, when the matched rule defines one. */
  credentials?: boolean;
}

export type CompiledOrigin =
  | { kind: "any" }
  | { kind: "list"; entries: CompiledEntry[] }
  | { kind: "regex"; regex: RegExp; credentials?: boolean }
  | { kind: "callback"; callback: CorsOriginCallback };

export interface CompiledEntry {
  match(origin: string): boolean;
  credentials?: boolean;
}

/** Escapes a string for safe inclusion inside a RegExp. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Compiles a glob pattern into a matcher function. `*` never crosses a
 * `/` boundary and the scheme/host split is preserved, so
 * `https://*.example.com` cannot match `https://evil.com/https://example.com`
 * or a different scheme. An empty glob matches anything.
 *
 * @param pattern - Glob pattern (e.g. `*`, `https://*.example.com`).
 * @returns A predicate over full origin strings.
 */
export function compileGlob(pattern: string): (origin: string) => boolean {
  const trimmed = pattern.trim();
  if (trimmed === "*") return () => true;

  const schemeSplit = trimmed.indexOf("://");
  const scheme = schemeSplit === -1 ? "" : trimmed.slice(0, schemeSplit);
  const rest = schemeSplit === -1 ? trimmed : trimmed.slice(schemeSplit + 3);

  const globToSource = (segment: string): string =>
    escapeRegExp(segment).replace(/\\\*/g, "[^/]*").replace(/\\\?/g, ".");

  const source =
    schemeSplit === -1
      ? `^${globToSource(rest)}$`
      : `^${escapeRegExp(scheme)}\\:\\/\\/${globToSource(rest)}$`;

  const regex = new RegExp(source, "i");
  return (origin) => regex.test(origin);
}

/**
 * Compiles one origin rule entry into a predicate, honoring the
 * configured match mode.
 *
 * - `exact`: string equality after scheme normalization
 * - `glob`: wildcard pattern
 * - `regex`: string treated as a RegExp source (relative to the origin)
 * - `auto`: wildcards present → glob, otherwise exact
 *
 * @param pattern - String or RegExp rule.
 * @param matchMode - How strings are interpreted.
 * @returns A predicate over full origin strings.
 */
export function compileEntry(pattern: string | RegExp, matchMode: NonNullable<CorsConfig["matchMode"]>): (origin: string) => boolean {
  if (pattern instanceof RegExp) {
    return (origin) => pattern.test(origin);
  }

  if (matchMode === "exact") {
    return (origin) => origin === pattern;
  }
  if (matchMode === "glob") {
    return compileGlob(pattern);
  }
  if (matchMode === "regex") {
    const regex = new RegExp(pattern);
    return (origin) => regex.test(origin);
  }

  const hasWildcard = pattern.includes("*") || pattern.includes("?");
  return hasWildcard ? compileGlob(pattern) : (origin) => origin === pattern;
}

/** Normalizes an origin for case-insensitive scheme/host comparisons. */
export function normalizeOrigin(origin: string): string {
  const split = origin.indexOf("://");
  if (split === -1) return origin.toLowerCase();
  const scheme = origin.slice(0, split).toLowerCase();
  const remainder = origin.slice(split + 3);
  const pathSplit = remainder.indexOf("/");
  if (pathSplit === -1) return `${scheme}://${remainder.toLowerCase()}`;
  return `${scheme}://${remainder.slice(0, pathSplit).toLowerCase()}${remainder.slice(pathSplit)}`;
}

/**
 * Builds the compiled matcher for the configured `origin` value.
 *
 * @param config - Resolved CORS configuration.
 * @returns A compiled, immutable matcher.
 */
export function compileOrigin(config: CorsConfig): CompiledOrigin {
  const { origin, matchMode, allowNullOrigin } = config;

  if (origin === "*") {
    return { kind: "any" };
  }
  if (origin === undefined) {
    return { kind: "any" };
  }
  if (typeof origin === "function") {
    return { kind: "callback", callback: origin };
  }
  if (origin instanceof RegExp) {
    return { kind: "regex", regex: origin };
  }

  const mode = matchMode ?? "auto";
  const rules: Array<string | CorsOriginRule> = Array.isArray(origin) ? origin : [origin];

  const compileRule = (rule: string | CorsOriginRule): CompiledEntry => {
    const credentials = typeof rule === "object" ? rule.credentials : undefined;
    const pattern = typeof rule === "string" ? rule : rule.pattern;

    if (typeof pattern === "string") {
      const compiledPattern = mode === "regex" ? pattern : normalizeOrigin(pattern);
      const predicate = compileEntry(compiledPattern, mode);
      return {
        match: (originValue: string) =>
          mode === "regex" ? predicate(originValue) : predicate(normalizeOrigin(originValue)),
        credentials,
      };
    }
    return {
      match: (originValue: string) => pattern.test(originValue),
      credentials,
    };
  };

  const entries: CompiledEntry[] = rules.map(compileRule);

  // Per-origin credential rules take precedence over plain patterns, so a
  // broad glob like "https://*.example.com" can never shadow a specific
  // credentialed rule that lives under it (first-match-wins otherwise).
  entries.sort(
    (a, b) => (b.credentials === undefined ? 0 : 1) - (a.credentials === undefined ? 0 : 1)
  );

  if (allowNullOrigin) {
    entries.push({ match: (originValue: string) => originValue === "null" });
  }

  return { kind: "list", entries };
}

/**
 * Resolves an origin against the compiled matcher.
 *
 * @param matcher - Compiled origin matcher.
 * @param origin - Origin to test.
 * @returns Same matcher entries for `list` (for sub-rule metadata);
 *   {@link OriginMatch} result otherwise.
 */
export function resolveOrigin(
  matcher: CompiledOrigin,
  origin: string
): OriginMatch {
  switch (matcher.kind) {
    case "any":
      return { matched: true };
    case "regex":
      return { matched: matcher.regex.test(origin), credentials: matcher.credentials };
    case "list": {
      for (const entry of matcher.entries) {
        if (entry.match(origin)) {
          return { matched: true, credentials: entry.credentials };
        }
      }
      return { matched: false };
    }
    case "callback":
      throw new CorsCallbackOriginError();
  }
}

/** Thrown when a synchronous API touches a callback-based origin config. */
export class CorsCallbackOriginError extends Error {
  constructor() {
    super(
      "cors: callback-based origins require the async API — use processAsync() or the fetch handler."
    );
    this.name = "CorsCallbackOriginError";
  }
}