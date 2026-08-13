import { describe, expect, test } from "bun:test";
import { Csp, CspOptionsError, buildCsp, parseCsp, serializeCsp, CSP_HEADER, CSP_REPORT_ONLY_HEADER } from "../../src/csp/index";
import { resolveCspConfig } from "../../src/csp/index";

describe("csp core: serialization", () => {
  test("directives are sorted, sources keep configured order", () => {
    const policy = serializeCsp({
      "frame-ancestors": ["'none'"],
      "default-src": ["'self'"],
      "script-src": ["'self'", "https://cdn.example.com"],
    });
    expect(policy).toBe("default-src 'self'; frame-ancestors 'none'; script-src 'self' https://cdn.example.com");
  });

  test("empty directives serialize to their bare name", () => {
    expect(serializeCsp({ "upgrade-insecure-requests": [] })).toBe("upgrade-insecure-requests");
  });

  test("parse/serialize round-trips", () => {
    const original = "base-uri 'self'; default-src 'self'; frame-ancestors 'none'; img-src https: data:; object-src 'none'";
    expect(serializeCsp(parseCsp(original).directives)).toBe(original);
  });

  test("parse lowercases directive names and splits sources", () => {
    const parsed = parseCsp("SCRIPT-SRC 'self' https://a.example.com; FRAME-ANCESTORS 'none'");
    expect(parsed.directives).toEqual({
      "script-src": ["'self'", "https://a.example.com"],
      "frame-ancestors": ["'none'"],
    });
  });

  test("parse rejects duplicates, commas and hostile input", () => {
    expect(() => parseCsp("default-src 'self'; default-src 'none'")).toThrow(CspOptionsError);
    expect(() => parseCsp("default-src 'self', img-src https:")).toThrow(CspOptionsError);
    expect(() => parseCsp("default-src 'self'; evil-src a\u0000b")).toThrow(CspOptionsError);
    expect(() => parseCsp("")).toThrow(CspOptionsError);
    expect(() => parseCsp(" ; ")).toThrow(CspOptionsError);
  });
});

describe("csp core: build", () => {
  test("default policy builds deterministically", () => {
    const config = resolveCspConfig();
    const a = buildCsp(config);
    const b = buildCsp(config);
    expect(Object.entries(a.headers)).toEqual(Object.entries(b.headers));
    expect(a.headers[CSP_HEADER]).toBe(
      "base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    );
    expect(a.headers[CSP_REPORT_ONLY_HEADER]).toBeUndefined();
  });

  test("reportOnly swaps the header name", () => {
    const config = resolveCspConfig({ reportOnly: true });
    const { headers } = buildCsp(config);
    expect(headers[CSP_REPORT_ONLY_HEADER]).toBe("base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'");
    expect(headers[CSP_HEADER]).toBeUndefined();
  });

  test("nonce templates are replaced from the context", () => {
    const config = resolveCspConfig({ preset: "strict" });
    const { headers } = buildCsp(config, { nonce: "abc123" });
    expect(headers[CSP_HEADER]).toBe(
      "base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'"
    );
  });

  test("building a nonce policy without a nonce throws (fail loud)", () => {
    const config = resolveCspConfig({ preset: "strict" });
    expect(() => buildCsp(config)).toThrow(CspOptionsError);
    expect(() => buildCsp(config, { nonce: "" })).toThrow(CspOptionsError);
    expect(() => buildCsp(config, { nonce: "bad nonce!" })).toThrow(CspOptionsError);
  });

  test("nonce policies are still deterministic across equal contexts", () => {
    const config = resolveCspConfig({ preset: "strict" });
    const a = buildCsp(config, { nonce: "x" });
    const b = buildCsp(config, { nonce: "x" });
    expect(Object.entries(a.headers)).toEqual(Object.entries(b.headers));
  });

  test("context without nonce works for nonce-free configs", () => {
    const config = resolveCspConfig();
    expect(buildCsp(config, {}).headers[CSP_HEADER]).toContain("default-src 'self'");
  });
});

describe("csp module surface", () => {
  test("headers() returns a Web-standard Headers view", () => {
    const headers = Csp().headers();
    expect(headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(headers.get("Content-Security-Policy-Report-Only")).toBeNull();
  });

  test("policy() returns the serialized string", () => {
    expect(Csp({ preset: "minimal" }).policy()).toBe("base-uri 'self'; frame-ancestors 'none'; object-src 'none'");
    expect(Csp({ preset: "strict" }).policy({ nonce: "n1" })).toContain("'nonce-n1' 'strict-dynamic'");
  });

  test("module.parse is the strict parser", () => {
    const csp = Csp();
    expect(csp.parse("img-src https:").directives).toEqual({ "img-src": ["https:"] });
    expect(() => csp.parse("img-src https:, data:")).toThrow(CspOptionsError);
  });

  test("all surfaces agree on the same configuration", () => {
    const csp = Csp({ preset: "minimal", reportOnly: true });
    expect(csp.policy()).toBe(csp.headers().get("Content-Security-Policy-Report-Only"));
    expect(Object.values(csp.build().headers)[0]).toBe(csp.policy());
  });
});