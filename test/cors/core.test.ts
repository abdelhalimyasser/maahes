import { describe, expect, test } from "bun:test";
import {
  createEngine,
  existingVary,
  headerValue,
  isHeaderSubset,
  isPreflight,
  mergeVary,
  parseCsv,
  sortHeaderNames,
  sortMethods,
} from "../../src/cors/core";
import { compileOrigin } from "../../src/cors/matchers";
import { resolveConfig } from "../../src/cors/config";
import type { CorsConfig } from "../../src/cors/types";

const engine = (config: CorsConfig) => {
  const resolved = resolveConfig(config);
  return createEngine(resolved, compileOrigin(resolved));
};

describe("CORS core - header utilities", () => {
  test("headerValue reads case-insensitively and takes the first array entry", () => {
    const headers = { Origin: "https://a.example.com", "X-Multi": ["first", "second"] };
    expect(headerValue(headers, "origin")).toBe("https://a.example.com");
    expect(headerValue(headers, "x-multi")).toBe("first");
    expect(headerValue(headers, "missing")).toBeUndefined();
    expect(headerValue(undefined, "origin")).toBeUndefined();
  });

  test("existingVary preserves first-use casing", () => {
    expect(existingVary({ vary: "Accept-Encoding, User-Agent" })).toEqual(["Accept-Encoding", "User-Agent"]);
    expect(existingVary({ vary: "  " })).toBeUndefined();
    expect(existingVary(undefined)).toBeUndefined();
  });

  test("mergeVary appends without duplicates, case-insensitively", () => {
    expect(mergeVary(["Accept-Encoding"], ["Origin"])).toEqual(["Accept-Encoding", "Origin"]);
    expect(mergeVary(["Origin"], ["Origin", "Access-Control-Request-Method"])).toEqual([
      "Origin",
      "Access-Control-Request-Method",
    ]);
    expect(mergeVary(undefined, ["Origin", "Origin"])).toEqual(["Origin"]);
    expect(mergeVary(["origin"], ["Origin"])).toEqual(["origin"]);
  });

  test("sortMethods orders common methods canonically, the rest alphabetically", () => {
    expect(sortMethods(["POST", "GET", "PATCH"])).toEqual(["GET", "PATCH", "POST"]);
    expect(sortMethods(["ZAP", "GET", "ACL"])).toEqual(["GET", "ACL", "ZAP"]);
  });

  test("sortHeaderNames sorts lexicographically with stable ties", () => {
    expect(sortHeaderNames(["Z-Header", "A-Header", "M-Header"])).toEqual(["A-Header", "M-Header", "Z-Header"]);
  });

  test("isHeaderSubset compares case-insensitively", () => {
    expect(isHeaderSubset(["Content-Type", "X-Token"], ["content-type", "x-token"])).toBe(true);
    expect(isHeaderSubset(["Content-Type", "X-Other"], ["content-type"])).toBe(false);
  });

  test("parseCsv trims, dedupes and preserves order", () => {
    expect(parseCsv(" content-type , x-token, CONTENT-TYPE ")).toEqual(["content-type", "x-token"]);
    expect(parseCsv(undefined)).toEqual([]);
    expect(parseCsv("")).toEqual([]);
  });
});

describe("CORS core - preflight detection", () => {
  const input = {
    method: "OPTIONS",
    headers: { origin: "https://a.example.com", "access-control-request-method": "DELETE" },
  };

  test("'auto' requires OPTIONS + Access-Control-Request-Method", () => {
    expect(isPreflight(input, "auto")).toBe(true);
    expect(isPreflight({ ...input, headers: {} }, "auto")).toBe(false);
    expect(isPreflight({ method: "GET", headers: input.headers }, "auto")).toBe(false);
  });

  test("'always' treats every OPTIONS as a preflight", () => {
    expect(isPreflight({ ...input, headers: {} }, "always")).toBe(true);
  });

  test("'never' never treats OPTIONS as a preflight", () => {
    expect(isPreflight(input, "never")).toBe(false);
  });
});

describe("CORS core - origin resolution", () => {
  test("a request without Origin is never a CORS request", () => {
    const result = engine({}).process({ method: "GET" });
    expect(result.allowed).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.origin).toBeNull();
    expect(result.headers["Access-Control-Allow-Origin"]).toBeUndefined();
  });

  test("wildcard config reflects the actual origin when credentials are enabled", () => {
    const result = engine({ credentials: true }).process({
      method: "GET",
      headers: { origin: "https://x.example.com" },
    });
    expect(result.headers["Access-Control-Allow-Origin"]).toBe("https://x.example.com");
    expect(result.headers["Access-Control-Allow-Credentials"]).toBe("true");
  });

  test("wildcard config emits a literal '*' without credentials", () => {
    const result = engine({}).process({ method: "GET", headers: { origin: "https://x.example.com" } });
    expect(result.headers["Access-Control-Allow-Origin"]).toBe("*");
    expect(result.headers["Access-Control-Allow-Credentials"]).toBeUndefined();
  });

  test("per-origin credentials override the global flag", () => {
    const config: CorsConfig = {
      origin: [{ pattern: "https://secure.example.com", credentials: true }],
      credentials: false,
    };
    const granted = engine(config).process({
      method: "GET",
      headers: { origin: "https://secure.example.com" },
    });
    expect(granted.headers["Access-Control-Allow-Credentials"]).toBe("true");

    const denied = engine(config).process({
      method: "GET",
      headers: { origin: "https://other.example.com" },
    });
    expect(denied.allowed).toBe(false);
  });

  test("denied origins omit headers and stay blocked", () => {
    const result = engine({ origin: ["https://app.example.com"] }).process({
      method: "GET",
      headers: { origin: "https://evil.com" },
    });
    expect(result.allowed).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.statusCode).toBeUndefined();
    expect(Object.keys(result.headers)).toHaveLength(0);
  });

  test("failureStatus hard-blocks denied simple requests", () => {
    const result = engine({ origin: ["https://app.example.com"], failureStatus: 403 }).process({
      method: "GET",
      headers: { origin: "https://evil.com" },
    });
    expect(result.allowed).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.headers["Vary"]).toBe("Origin");
  });

  test("exposedHeaders are emitted sorted", () => {
    const result = engine({ exposedHeaders: ["x-total", "ETag"] }).process({
      method: "GET",
      headers: { origin: "https://a.example.com" },
    });
    expect(result.headers["Access-Control-Expose-Headers"]).toBe("ETag, x-total");
  });
});

describe("CORS core - preflight handling", () => {
  const preflight = {
    method: "OPTIONS",
    headers: {
      origin: "https://app.example.com",
      "access-control-request-method": "PATCH",
    },
  };

  test("successful preflight returns 204 with full header set", () => {
    const result = engine({ origin: "*", methods: ["GET", "PATCH"] }).process(preflight);
    expect(result.allowed).toBe(true);
    expect(result.preflight).toBe(true);
    expect(result.statusCode).toBe(204);
    expect(result.headers["Access-Control-Allow-Methods"]).toBe("GET, PATCH");
    expect(result.headers["Access-Control-Max-Age"]).toBe("86400");
    expect(result.headers["Vary"]).toBe("Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
  });

  test("preflight reflects requested headers under allowedHeaders: true", () => {
    const result = engine({}).process({
      ...preflight,
      headers: { ...preflight.headers, "access-control-request-headers": "content-type, x-token" },
    });
    expect(result.headers["Access-Control-Allow-Headers"]).toBe("content-type, x-token");
  });

  test("preflight omits Allow-Headers when nothing was requested", () => {
    const result = engine({}).process(preflight);
    expect(result.headers["Access-Control-Allow-Headers"]).toBeUndefined();
  });

  test("preflight with a configured header list validates the subset", () => {
    const config: CorsConfig = { allowedHeaders: ["content-type", "x-token"] };
    const ok = engine(config).process({
      ...preflight,
      headers: { ...preflight.headers, "access-control-request-headers": "x-token, content-type" },
    });
    expect(ok.allowed).toBe(true);
    expect(ok.headers["Access-Control-Allow-Headers"]).toBe("content-type, x-token");

    const denied = engine(config).process({
      ...preflight,
      headers: { ...preflight.headers, "access-control-request-headers": "x-evil" },
    });
    expect(denied.allowed).toBe(false);
    expect(denied.statusCode).toBe(403);
  });

  test("preflight with a disallowed method is rejected with 403", () => {
    const result = engine({ methods: ["GET"] }).process(preflight);
    expect(result.allowed).toBe(false);
    expect(result.statusCode).toBe(403);
  });

  test("preflight with optionsSuccessStatus honors the custom status", () => {
    const result = engine({ optionsSuccessStatus: 200 }).process(preflight);
    expect(result.statusCode).toBe(200);
  });

  test("custom maxAge is emitted as a string", () => {
    const result = engine({ maxAge: 120 }).process(preflight);
    expect(result.headers["Access-Control-Max-Age"]).toBe("120");
  });
});

describe("CORS core - Private Network Access", () => {
  const pna = {
    method: "OPTIONS",
    headers: {
      origin: "https://app.example.com",
      "access-control-request-method": "GET",
      "access-control-request-private-network": "true",
    },
  };

  test("denied by default with a 403", () => {
    const result = engine({}).process(pna);
    expect(result.allowed).toBe(false);
    expect(result.statusCode).toBe(403);
  });

  test("allowed when allowPrivateNetwork is enabled", () => {
    const result = engine({ allowPrivateNetwork: true }).process(pna);
    expect(result.allowed).toBe(true);
    expect(result.headers["Access-Control-Allow-Private-Network"]).toBe("true");
  });

  test("no Private-Network header on plain preflights", () => {
    const result = engine({ allowPrivateNetwork: true }).process({
      method: "OPTIONS",
      headers: { origin: "https://app.example.com", "access-control-request-method": "GET" },
    });
    expect(result.headers["Access-Control-Allow-Private-Network"]).toBeUndefined();
  });
});

describe("CORS core - hooks", () => {
  test("onBlock fires for denied origins and receives the raw origin", () => {
    const seen: Array<{ origin: string | null }> = [];
    const result = engine({
      origin: ["https://app.example.com"],
      onBlock: (context) => seen.push(context),
    }).process({ method: "GET", headers: { origin: "https://evil.com" } });

    expect(result.allowed).toBe(false);
    expect(seen).toEqual([{ origin: "https://evil.com", request: { method: "GET", headers: { origin: "https://evil.com" } } }]);
  });

  test("onPreflight fires with the resolved result", () => {
    const seen: unknown[] = [];
    const result = engine({
      onPreflight: (context) => seen.push({ origin: context.origin, allowed: context.result.allowed }),
    }).process({
      method: "OPTIONS",
      headers: { origin: "https://app.example.com", "access-control-request-method": "GET" },
    });

    expect(result.allowed).toBe(true);
    expect(seen).toEqual([{ origin: "https://app.example.com", allowed: true }]);
  });
});

describe("CORS core - determinism", () => {
  test("header keys follow the fixed RESPONSE_HEADERS order", () => {
    const result = engine({ exposedHeaders: ["x-1"], methods: ["POST", "GET"] }).process({
      method: "OPTIONS",
      headers: {
        origin: "https://a.example.com",
        "access-control-request-method": "POST",
        "access-control-request-headers": "x-token",
      },
    });
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
    const keys = Object.keys(result.headers);
    const positions = order.map((name) => keys.indexOf(name));
    const sorted = [...positions].sort((a, b) => a - b);
    expect(positions.filter((p) => p !== -1)).toEqual(sorted.filter((p) => p !== -1));
  });
});