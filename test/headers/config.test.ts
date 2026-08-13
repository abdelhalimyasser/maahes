import { describe, expect, test } from "bun:test";
import {
  SecurityHeaders,
  SecurityHeadersOptionsError,
  DEFAULT_HEADERS_CONFIG,
  PRESETS,
  parseHeadersConfigInput,
  resolveHeadersConfig,
} from "../../src/headers/index";

describe("SecurityHeaders config: defaults and presets", () => {
  test("defaults resolve to the 'default' preset", () => {
    const config = resolveHeadersConfig();
    expect(config.preset).toBe("default");
    expect(config.nosniff).toBe(true);
    expect(config.frameOptions).toBe("DENY");
    expect(config.referrerPolicy).toBe("strict-origin-when-cross-origin");
    expect(config.hsts).toEqual({ maxAge: 31536000, includeSubDomains: true, preload: false });
    expect(config.coop).toBe("same-origin");
    expect(config.coep).toBe("credentialless");
    expect(config.corp).toBe(false);
    expect(config.permissionsPolicy).toContain("geolocation");
    expect(config.permissionsPolicy).not.toContain("interest-cohort");
    expect(config.xssProtection).toBe("0");
    expect(config.crossDomainPolicy).toBe("none");
    expect(config.httpsOnly).toBe(true);
    expect(config.overwrite).toBe(true);
  });

  test("minimal preset disables cross-origin isolation and legacy extras", () => {
    const config = resolveHeadersConfig({ preset: "minimal" });
    expect(config.coop).toBe(false);
    expect(config.coep).toBe(false);
    expect(config.permissionsPolicy).toBe(false);
    expect(config.xssProtection).toBe(false);
    expect(config.crossDomainPolicy).toBe(false);
    expect(config.nosniff).toBe(true);
    expect(config.frameOptions).toBe("DENY");
  });

  test("strict preset adds CORP same-origin and no-referrer", () => {
    const config = resolveHeadersConfig({ preset: "strict" });
    expect(config.corp).toBe("same-origin");
    expect(config.referrerPolicy).toBe("no-referrer");
  });

  test("user overrides beat presets (deep merge)", () => {
    const config = resolveHeadersConfig({ preset: "strict", corp: false });
    expect(config.corp).toBe(false);
    const minimal = resolveHeadersConfig({ preset: "minimal", coop: "same-origin" });
    expect(minimal.coop).toBe("same-origin");
  });
});

describe("SecurityHeaders config: validation (fail fast)", () => {
  test("rejects invalid enum values", () => {
    expect(() => resolveHeadersConfig({ frameOptions: "ALLOWALL" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ coop: "same-origin-xyz" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ coep: "require-corp!" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ corp: "no-store" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ xssProtection: "1; mode=banana" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ referrerPolicy: "https://evil" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ crossDomainPolicy: "sometimes" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ preset: "extreme" as never })).toThrow(SecurityHeadersOptionsError);
  });

  test("rejects invalid HSTS combinations", () => {
    expect(() => resolveHeadersConfig({ hsts: { maxAge: -1 } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ hsts: { maxAge: 1.5 } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ hsts: { maxAge: 600, preload: true } })).toThrow(SecurityHeadersOptionsError);
    expect(() =>
      resolveHeadersConfig({ hsts: { maxAge: 31536000, preload: true, includeSubDomains: false } })
    ).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ hsts: { maxAge: 31536000, preload: true } })).not.toThrow();
  });

  test("rejects non-boolean flags", () => {
    expect(() => resolveHeadersConfig({ httpsOnly: "yes" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ overwrite: 1 as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ nosniff: 0 as never })).toThrow(SecurityHeadersOptionsError);
  });

  test("rejects invalid extra header names and CRLF values", () => {
    expect(() => resolveHeadersConfig({ extra: { "bad name": "x" } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ extra: { "X-OK": "good\r\nInjected: 1" } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ extra: { "X-OK": "bad\nvalue" } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ extra: { "X-OK": "bad\u0000value" } })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ extra: { "X-OK": "tabs\tand spaces fine" } })).not.toThrow();
  });

  test("rejects invalid remove entries and remove/extra conflicts", () => {
    expect(() => resolveHeadersConfig({ remove: ["X Bad"] })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ remove: [""] })).toThrow(SecurityHeadersOptionsError);
    expect(() => resolveHeadersConfig({ remove: ["Server"], extra: { server: "nginx" } })).toThrow(
      SecurityHeadersOptionsError
    );
  });
});

describe("SecurityHeaders config: input formats", () => {
  test("accepts inline JSON strings with a headers wrapper", () => {
    const config = resolveHeadersConfig(parseHeadersConfigInput('{"headers":{"preset":"minimal"}}'));
    expect(config.preset).toBe("minimal");
    expect(() => resolveHeadersConfig(parseHeadersConfigInput('{"headers":{"hsts":{"maxAge":-1}}}'))).toThrow(
      SecurityHeadersOptionsError
    );
  });

  test("rejects malformed input", () => {
    expect(() => parseHeadersConfigInput("[]" as never)).toThrow(SecurityHeadersOptionsError);
    expect(() => parseHeadersConfigInput("[1,2]" as never)).toThrow(SecurityHeadersOptionsError);
    expect(() => parseHeadersConfigInput("{not json")).toThrow();
  });
});

describe("SecurityHeaders factory", () => {
  test("SecurityHeaders() constructs with defaults and shares the immutable instance", () => {
    const headers = SecurityHeaders();
    expect(headers.build().headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers).toBe(headers); // instance is share-safe by design (no mutation)
  });

  test("invalid configuration throws SecurityHeadersOptionsError at construction", () => {
    expect(() => SecurityHeaders({ hsts: { preload: true, maxAge: 60 } })).toThrow(SecurityHeadersOptionsError);
    expect(() => SecurityHeaders({ extra: { "X": "a\nb" } })).toThrow(SecurityHeadersOptionsError);
  });

  test("DEFAULT_HEADERS_CONFIG is exposed for introspection", () => {
    expect(DEFAULT_HEADERS_CONFIG.coop).toBe("same-origin");
    expect(PRESETS.strict.corp).toBe("same-origin");
  });
});