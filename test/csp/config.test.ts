import { describe, expect, test } from "bun:test";
import { Csp, CspOptionsError, DEFAULT_CSP_CONFIG, CSP_PRESETS, parseCspConfigInput, resolveCspConfig } from "../../src/csp/index";

describe("csp config: defaults and presets", () => {
  test("defaults resolve to a safe baseline", () => {
    const config = resolveCspConfig();
    expect(config.preset).toBe("default");
    expect(config.reportOnly).toBe(false);
    expect(config.directives["default-src"]).toEqual(["'self'"]);
    expect(config.directives["frame-ancestors"]).toEqual(["'none'"]);
    expect(config.directives["object-src"]).toEqual(["'none'"]);
    expect(config.directives["base-uri"]).toEqual(["'self'"]);
  });

  test("minimal preset never constrains script loading", () => {
    const config = resolveCspConfig({ preset: "minimal" });
    expect(config.directives["default-src"]).toBeUndefined();
    expect(config.directives["script-src"]).toBeUndefined();
    expect(config.directives["frame-ancestors"]).toEqual(["'none'"]);
  });

  test("strict preset is the nonce-based strict-dynamic pattern", () => {
    const config = resolveCspConfig({ preset: "strict" });
    expect(config.directives["script-src"]).toEqual(["'nonce-$nonce'", "'strict-dynamic'"]);
    expect(config.directives["object-src"]).toEqual(["'none'"]);
    expect(config.directives["base-uri"]).toEqual(["'self'"]);
  });

  test("user directives merge per name, replacing preset values", () => {
    const config = resolveCspConfig({ directives: { "default-src": ["https://cdn.example.com"] } });
    expect(config.directives["default-src"]).toEqual(["https://cdn.example.com"]);
    expect(config.directives["frame-ancestors"]).toEqual(["'none'"]); // untouched
    const added = resolveCspConfig({ directives: { "connect-src": ["https://api.example.com"] } });
    expect(added.directives["connect-src"]).toEqual(["https://api.example.com"]);
  });

  test("single string values and case-insensitive directive names normalize", () => {
    const config = resolveCspConfig({ directives: { "SCRIPT-SRC": "'self'" } });
    expect(config.directives["script-src"]).toEqual(["'self'"]);
  });
});

describe("csp config: validation (fail fast)", () => {
  test("rejects invalid preset and reportOnly types", () => {
    expect(() => resolveCspConfig({ preset: "extreme" as never })).toThrow(CspOptionsError);
    expect(() => resolveCspConfig({ reportOnly: "yes" as never })).toThrow(CspOptionsError);
  });

  test("rejects hostile directive names", () => {
    for (const name of ["bad name", "bad;name", "bad,dir", "bad\u0000name", "", "X\u007F"]) {
      expect(() => resolveCspConfig({ directives: { [name]: ["'self'"] } })).toThrow(CspOptionsError);
    }
  });

  test("rejects injection in source values", () => {
    const hostile = [
      "x\r\nSet-Cookie: pwned=1",
      "x; default-src 'none'",
      "'self', 'none'",
      "https://a\"b",
      "a\u0000b",
    ];
    for (const source of hostile) {
      expect(() => resolveCspConfig({ directives: { "script-src": [source] } })).toThrow(CspOptionsError);
    }
    // Raw policies: control characters survive directive splitting and are rejected.
    for (const policy of ["script-src a\u0007b", "script-src a\u0000b", "script-src 'self'\u001F"]) {
      expect(() => parseCspConfigInput(policy)).toThrow(CspOptionsError);
    }
  });

  test("'none' must be a directive's sole source", () => {
    expect(() => resolveCspConfig({ directives: { "object-src": ["'none'", "'self'"] } })).toThrow(CspOptionsError);
    expect(() => resolveCspConfig({ directives: { "object-src": ["'none'"] } })).not.toThrow();
  });

  test("nonce templates are constrained to the 'nonce-$nonce' form", () => {
    expect(() => resolveCspConfig({ directives: { "script-src": ["$nonce"] } })).toThrow(CspOptionsError);
    expect(() => resolveCspConfig({ directives: { "script-src": ["'nonce-$nonce'", "'strict-dynamic'"] } })).not.toThrow();
    expect(() => resolveCspConfig({ directives: { "script-src": ["https://x?$nonce"] } })).toThrow(CspOptionsError);
  });

  test("empty sources are rejected", () => {
    expect(() => resolveCspConfig({ directives: { "script-src": [""] } })).toThrow(CspOptionsError);
  });
});

describe("csp config: input formats", () => {
  test("accepts inline JSON strings with a csp wrapper", () => {
    const config = resolveCspConfig(parseCspConfigInput('{"csp":{"preset":"minimal"}}'));
    expect(config.preset).toBe("minimal");
    expect(() => resolveCspConfig(parseCspConfigInput('{"csp":{"directives":{"script-src":["x;y"]}}}'))).toThrow(
      CspOptionsError
    );
  });

  test("treats non-JSON, non-file strings as raw policies", () => {
    const config = parseCspConfigInput("default-src 'self'; frame-ancestors 'none'");
    expect(config.directives).toEqual({ "default-src": ["'self'"], "frame-ancestors": ["'none'"] });
  });

  test("rejects malformed raw policies", () => {
    expect(() => parseCspConfigInput("default-src 'self'; default-src 'none'")).toThrow(CspOptionsError);
    expect(() => parseCspConfigInput("")).toThrow(CspOptionsError);
    expect(() => parseCspConfigInput("  ;  ")).toThrow(CspOptionsError);
  });
});

describe("csp factory", () => {
  test("Csp() constructs with defaults and exposes the canonical defaults", () => {
    const csp = Csp();
    expect(csp.policy()).toContain("default-src 'self'");
    expect(DEFAULT_CSP_CONFIG.preset).toBe("default");
    expect(CSP_PRESETS.strict.directives?.["script-src"]).toEqual(["'nonce-$nonce'", "'strict-dynamic'"]);
  });

  test("invalid configuration throws CspOptionsError at construction", () => {
    expect(() => Csp({ directives: { "x-src": ["a;b"] } })).toThrow(CspOptionsError);
    expect(() => Csp("script-src 'none' 'self'")).toThrow(CspOptionsError);
  });

  test("Csp(raw policy) builds exactly that policy", () => {
    const csp = Csp("img-src https: data:; frame-ancestors 'none'");
    expect(csp.policy()).toBe("frame-ancestors 'none'; img-src https: data:");
  });
});