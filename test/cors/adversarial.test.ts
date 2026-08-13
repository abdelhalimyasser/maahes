import { describe, expect, test } from "bun:test";
import { Cors } from "../../src/cors/index";

describe("cors adversarial: malformed and hostile origins", () => {
  const cors = Cors({ origin: ["https://app.example.com"] });

  test("origins with CRLF / control characters never match and never crash", () => {
    const hostile = [
      "https://app.example.com\r\nSet-Cookie: evil=1",
      "https://app.example.com\nX-Evil: 1",
      "https://evil.com\r\nOrigin: https://app.example.com",
      "https://app.example.com\u0000",
      "\t",
    ];
    for (const origin of hostile) {
      const result = cors.process({ method: "GET", headers: { origin } });
      expect(result.allowed).toBe(false);
    }
  });

  test("origin header values are never reflected verbatim when denied", () => {
    const hostile = "https://app.example.com\r\nSet-Cookie: evil=1";
    const result = cors.process({ method: "GET", headers: { origin: hostile } });
    expect(Object.values(result.headers).join("\n")).not.toContain("Set-Cookie");
  });

  test("malformed origins (no scheme, path-only, junk) never match exact rules", () => {
    for (const origin of ["app.example.com", "https://app.example.com/path", "https://", "null", "undefined"]) {
      const result = cors.process({ method: "GET", headers: { origin } });
      expect(result.allowed).toBe(false);
    }
  });

  test("the literal 'null' origin is denied unless allowNullOrigin is set", () => {
    const denied = Cors({ origin: ["https://app.example.com"] }).process({
      method: "GET",
      headers: { origin: "null" },
    });
    expect(denied.allowed).toBe(false);

    const allowed = Cors({ origin: ["https://app.example.com"], allowNullOrigin: true }).process({
      method: "GET",
      headers: { origin: "null" },
    });
    expect(allowed.allowed).toBe(true);
    expect(allowed.headers["Access-Control-Allow-Origin"]).toBe("null");
  });

  test("origin matching is case-insensitive on scheme and host", () => {
    const mixed = cors.process({ method: "GET", headers: { origin: "HTTPS://APP.EXAMPLE.COM" } });
    expect(mixed.allowed).toBe(true);
  });

  test("globs never cross the scheme boundary", () => {
    const globs = Cors({ origin: ["https://*.example.com"] });
    expect(globs.process({ method: "GET", headers: { origin: "https://ok.example.com" } }).allowed).toBe(true);
    expect(globs.process({ method: "GET", headers: { origin: "http://ok.example.com" } }).allowed).toBe(false);
    expect(
      globs.process({ method: "GET", headers: { origin: "https://evil.com/https://ok.example.com" } }).allowed
    ).toBe(false);
  });
});

describe("cors adversarial: multiple and repeated headers", () => {
  test("multiple Origin header values take the first entry deterministically", () => {
    const cors = Cors({ origin: ["https://first.example.com", "https://second.example.com"] });
    const result = cors.process({
      method: "GET",
      headers: { origin: ["https://first.example.com", "https://second.example.com"] },
    });
    expect(result.allowed).toBe(true);
    expect(result.headers["Access-Control-Allow-Origin"]).toBe("https://first.example.com");

    // If the FIRST entry is hostile, the request must be denied even when a
    // later entry is allowed (no parser confusion, no smuggling).
    const hostileFirst = cors.process({
      method: "GET",
      headers: { origin: ["https://evil.io", "https://first.example.com"] },
    });
    expect(hostileFirst.allowed).toBe(false);
  });

  test("repeated case-variants of Origin resolve to the same value", () => {
    const cors = Cors({ origin: ["https://app.example.com"] });
    const result = cors.process({
      method: "GET",
      headers: { ORIGIN: "https://app.example.com", Origin: "https://evil.io" },
    });
    expect(result.allowed).toBe(true);
  });

  test("preflight header arrays resolve to the first entry (documented, smuggling-safe)", () => {
    const cors = Cors({ origin: ["https://app.example.com"] });
    const result = cors.process({
      method: "OPTIONS",
      headers: {
        origin: "https://app.example.com",
        "access-control-request-method": "POST",
        "access-control-request-headers": ["content-type, x-custom", "x-evil"],
      },
    });
    expect(result.allowed).toBe(true);
    expect(result.headers["Access-Control-Allow-Headers"]).toBe("content-type, x-custom");
  });
});

describe("cors adversarial: wildcard and credentials invariants", () => {
  test("credentials never pair with a literal '*'", () => {
    const cors = Cors({ credentials: true });
    const result = cors.process({ method: "GET", headers: { origin: "https://anywhere.example.com" } });
    expect(result.headers["Access-Control-Allow-Credentials"]).toBe("true");
    expect(result.headers["Access-Control-Allow-Origin"]).not.toBe("*");
  });

  test("preflight method comparison is case-insensitive", () => {
    const cors = Cors({ methods: ["GET", "POST"] });
    const ok = cors.process({
      method: "OPTIONS",
      headers: { origin: "https://x.example.com", "access-control-request-method": "post" },
    });
    expect(ok.allowed).toBe(true);
    const bad = cors.process({
      method: "OPTIONS",
      headers: { origin: "https://x.example.com", "access-control-request-method": "DELETE" },
    });
    expect(bad.allowed).toBe(false);
  });

  test("requested headers are validated case-insensitively against configured lists", () => {
    const cors = Cors({ origin: ["https://app.example.com"], allowedHeaders: ["Content-Type", "X-Token"] });
    const ok = cors.process({
      method: "OPTIONS",
      headers: {
        origin: "https://app.example.com",
        "access-control-request-method": "GET",
        "access-control-request-headers": "content-type, x-token",
      },
    });
    expect(ok.allowed).toBe(true);
  });
});

describe("cors adversarial: deterministic output", () => {
  test("the same request always produces the same header set (ordering stable)", () => {
    const cors = Cors({ origin: ["https://app.example.com"], exposedHeaders: ["x-a", "x-b"] });
    const request = {
      method: "OPTIONS",
      headers: {
        origin: "https://app.example.com",
        "access-control-request-method": "PATCH",
        "access-control-request-headers": "content-type",
      },
    };
    const a = cors.process(request);
    const b = cors.process(request);
    expect(Object.entries(a.headers)).toEqual(Object.entries(b.headers));
    const keys = Object.keys(a.headers);
    expect(keys).toEqual([...keys].sort((x, y) => {
      const order = [
        "Access-Control-Allow-Origin",
        "Access-Control-Expose-Headers",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Private-Network",
        "Access-Control-Max-Age",
        "Vary",
      ];
      return order.indexOf(x) - order.indexOf(y);
    }));
  });
});

describe("cors adversarial: hooks never receive secrets", () => {
  test("onBlock receives the origin but the engine never echoes headers back into it", () => {
    let seen: unknown;
    const cors = Cors({
      origin: ["https://app.example.com"],
      onBlock: (ctx) => {
        seen = ctx;
      },
    });
    const hostile = "https://evil.io\r\nX-Injected: 1";
    cors.process({ method: "GET", headers: { origin: hostile } });
    expect(seen).toMatchObject({ origin: hostile });
  });
});