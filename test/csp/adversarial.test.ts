import { describe, expect, test } from "bun:test";
import { Csp, CspOptionsError, serializeCsp } from "../../src/csp/index";
import { SecurityHeaders, SecurityHeadersOptionsError, KNOWN_HEADER_ORDER } from "../../src/headers/index";

describe("csp adversarial: injection and grammar abuse", () => {
  test("CRLF / response splitting is rejected in every source position", () => {
    const payloads = [
      "x\r\nContent-Security-Policy: default-src 'none'",
      "x\nx",
      "x\rx",
      "x\u0000x",
      "x\u001Fx",
      "x\u007Fx",
      "'self'\u0007",
    ];
    for (const source of payloads) {
      expect(() => Csp({ directives: { "script-src": [source] } })).toThrow(CspOptionsError);
    }
  });

  test("directive smuggling through names and values is impossible", () => {
    expect(() => Csp({ directives: { "default-src; frame-ancestors": ["'none'"] } })).toThrow(CspOptionsError);
    expect(() => Csp({ directives: { "default-src": ["'self'", "x; frame-ancestors 'none'"] } })).toThrow(
      CspOptionsError
    );
    expect(() => Csp("default-src 'self' \")); evil")).toThrow(CspOptionsError);
  });

  test("policy header injection via commas is impossible", () => {
    expect(() => Csp("default-src 'self', img-src https:")).toThrow(CspOptionsError);
  });

  test("unknown-but-valid directive names are accepted (future-proof)", () => {
    const csp = Csp({ directives: { "weird-future-directive": ["'self'"] } });
    expect(csp.policy()).toContain("weird-future-directive 'self'");
  });

  test("hostile presets and directive shapes fail fast", () => {
    expect(() => Csp({ directives: [] as never })).toThrow(CspOptionsError);
    expect(() => Csp({ directives: { "script-src": 42 as never } })).toThrow(CspOptionsError);
    expect(() => Csp({ directives: { "script-src": ["'none'", "'self'"] } })).toThrow(CspOptionsError);
  });
});

describe("csp adversarial: nonce handling", () => {
  test("nonce values are constrained to the CSP grammar", () => {
    const strict = Csp({ preset: "strict" });
    for (const bad of ["", "has space", "semi;colon", "comma,value", "quote\"", "new\nline"]) {
      expect(() => strict.policy({ nonce: bad })).toThrow(CspOptionsError);
    }
    for (const good of ["abc123", "A+b/c=_", "_-x9"]) {
      expect(strict.policy({ nonce: good })).toContain(`'nonce-${good}'`);
    }
  });

  test("nonce never leaks into report-only or non-nonce directives", () => {
    const csp = Csp({
      reportOnly: true,
      directives: { "script-src": ["'nonce-$nonce'"], "style-src": ["'self'"] },
    });
    const policy = csp.policy({ nonce: "secret" });
    expect(policy).toContain("'nonce-secret'");
    expect(policy).not.toContain("$nonce");
    expect(policy).toBe("base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'nonce-secret'; style-src 'self'");
  });
});

describe("csp adversarial: determinism and purity", () => {
  test("frozen configs are legal and never mutated", () => {
    const frozen = Object.freeze({
      directives: Object.freeze({ "script-src": Object.freeze(["'self'"]) }),
    });
    expect(() => Csp(frozen)).not.toThrow();
    expect(() => Csp(frozen).build()).not.toThrow();
  });

  test("identical configs produce identical policies", () => {
    const a = Csp({ directives: { "z-dir": ["'self'"], "a-dir": ["https://x"] } });
    const b = Csp({ directives: { "z-dir": ["'self'"], "a-dir": ["https://x"] } });
    expect(a.policy()).toBe(b.policy());
  });

  test("serialization never depends on insertion order", () => {
    const a = serializeForTest({ "z-dir": ["'self'"], "a-dir": ["'self'"] });
    const b = serializeForTest({ "a-dir": ["'self'"], "z-dir": ["'self'"] });
    expect(a).toBe(b);
    expect(a).toBe("a-dir 'self'; z-dir 'self'");
  });
});

describe("csp × headers integration", () => {
  test("SecurityHeaders emits CSP first when configured (string or config)", () => {
    const viaString = SecurityHeaders({ csp: "default-src 'self'" }).build();
    expect(viaString.headers["Content-Security-Policy"]).toBe("default-src 'self'");
    expect(Object.keys(viaString.headers)[0]).toBe("Content-Security-Policy");

    const viaConfig = SecurityHeaders({ csp: { directives: { "default-src": ["'self'"] } } }).build();
    // Config objects merge over the default preset's directives.
    expect(viaConfig.headers["Content-Security-Policy"]).toBe(
      "base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    );
  });

  test("reportOnly policies emit the report-only header", () => {
    const { headers } = SecurityHeaders({
      csp: { reportOnly: true, directives: { "default-src": ["'self'"] } },
    }).build();
    expect(headers["Content-Security-Policy-Report-Only"]).toBe(
      "base-uri 'self'; default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    );
    expect(headers["Content-Security-Policy"]).toBeUndefined();
  });

  test("no csp option → no CSP header (never a surprise policy)", () => {
    expect(SecurityHeaders().build().headers["Content-Security-Policy"]).toBeUndefined();
    expect(SecurityHeaders({ csp: false }).build().headers["Content-Security-Policy"]).toBeUndefined();
  });

  test("nonce templates are rejected in the headers channel", () => {
    expect(() => SecurityHeaders({ csp: { preset: "strict" } })).toThrow(SecurityHeadersOptionsError);
    expect(() => SecurityHeaders({ csp: "script-src 'nonce-$nonce' 'strict-dynamic'" })).toThrow(
      SecurityHeadersOptionsError
    );
  });

  test("invalid csp policies throw SecurityHeadersOptionsError at construction", () => {
    expect(() => SecurityHeaders({ csp: "default-src 'none' 'self'" })).toThrow(SecurityHeadersOptionsError);
    expect(() => SecurityHeaders({ csp: { directives: { "x-src": ["a;b"] } } })).toThrow(SecurityHeadersOptionsError);
  });

  test("CSP participates in overwrite semantics; own headers are governed by config keys", () => {
    const { headers } = SecurityHeaders({ csp: "default-src 'self'" }).build({
      existing: { "Content-Security-Policy": "default-src 'none'" },
    });
    expect(headers["Content-Security-Policy"]).toBe("default-src 'self'"); // overwrite wins

    // `remove` strips EXISTING headers; the engine's own CSP is governed
    // by the csp option (documented contract) — disable with csp: false.
    const own = SecurityHeaders({ csp: "default-src 'self'", remove: ["content-security-policy"] }).build({
      existing: { "Content-Security-Policy": "default-src 'none'" },
    });
    expect(own.headers["Content-Security-Policy"]).toBe("default-src 'self'");

    const stripped = SecurityHeaders({ csp: false, remove: ["content-security-policy"] }).build({
      existing: { "Content-Security-Policy": "default-src 'none'" },
    });
    expect(stripped.headers["Content-Security-Policy"]).toBeUndefined();

    const kept = SecurityHeaders({ csp: "default-src 'self'", overwrite: false }).build({
      existing: { "Content-Security-Policy": "default-src 'none'" },
    });
    expect(kept.headers["Content-Security-Policy"]).toBe("default-src 'none'");
  });

  test("extras cannot spoof the CSP header", () => {
    expect(() => SecurityHeaders({ extra: { "content-security-policy": "default-src 'none'" } })).toThrow(
      SecurityHeadersOptionsError
    );
  });

  test("KNOWN_HEADER_ORDER leads with CSP", () => {
    expect(KNOWN_HEADER_ORDER[0]).toBe("Content-Security-Policy");
    expect(KNOWN_HEADER_ORDER[1]).toBe("Content-Security-Policy-Report-Only");
    expect(KNOWN_HEADER_ORDER).toContain("Strict-Transport-Security");
  });

  test("adapters emit the CSP header end to end", async () => {
    const module = SecurityHeaders({ csp: "default-src 'self'" });
    const response = await module.fetchHandler(() => new Response("ok"))(new Request("https://x.example.com/"));
    expect(response.headers.get("Content-Security-Policy")).toBe("default-src 'self'");

    const resHeaders: Record<string, string> = {};
    module.middleware()(
      { socket: { encrypted: true } },
      { setHeader: (n, v) => (resHeaders[n] = v), getHeaders: () => resHeaders } as never,
      () => {}
    );
    expect(resHeaders["Content-Security-Policy"]).toBe("default-src 'self'");
  });
});

function serializeForTest(directives: Record<string, string[]>) {
  return serializeCsp(directives);
}