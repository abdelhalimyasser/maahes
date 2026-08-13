import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CorsOptionsError,
  DEFAULT_CORS_CONFIG,
  parseCorsConfigInput,
  resolveConfig,
} from "../../src/cors/config";

describe("CORS config - defaults", () => {
  test("secure baseline: wildcard origin, no credentials, long cache, auto preflight", () => {
    expect(DEFAULT_CORS_CONFIG.origin).toBe("*");
    expect(DEFAULT_CORS_CONFIG.credentials).toBe(false);
    expect(DEFAULT_CORS_CONFIG.maxAge).toBe(86400);
    expect(DEFAULT_CORS_CONFIG.preflight).toBe("auto");
    expect(DEFAULT_CORS_CONFIG.optionsSuccessStatus).toBe(204);
    expect(DEFAULT_CORS_CONFIG.allowPrivateNetwork).toBe(false);
    expect(DEFAULT_CORS_CONFIG.allowNullOrigin).toBe(false);
    expect(DEFAULT_CORS_CONFIG.matchMode).toBe("auto");
    expect(DEFAULT_CORS_CONFIG.allowedHeaders).toBe(true);
    expect(DEFAULT_CORS_CONFIG.exposedHeaders).toEqual([]);
  });

  test("resolveConfig() fills every default when given an empty config", () => {
    const resolved = resolveConfig({});
    expect(resolved.origin).toBe("*");
    expect(resolved.methods).toEqual(["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"]);
    expect(resolved.maxAge).toBe(86400);
    expect(resolved.preset).toBe("default");
    expect(resolved.failureStatus).toBeUndefined();
  });

  test("resolveConfig() keeps untouched defaults under partial overrides", () => {
    const resolved = resolveConfig({ credentials: true });
    expect(resolved.credentials).toBe(true);
    expect(resolved.origin).toBe("*");
    expect(resolved.preflight).toBe("auto");
    expect(resolved.maxAge).toBe(86400);
  });

  test("'express' preset switches preflight to 'always' while keeping other defaults", () => {
    const resolved = resolveConfig({ preset: "express" });
    expect(resolved.preflight).toBe("always");
    expect(resolved.credentials).toBe(false);
    expect(resolved.maxAge).toBe(86400);
  });

  test("explicit options beat preset values", () => {
    const resolved = resolveConfig({ preset: "express", preflight: "auto" });
    expect(resolved.preflight).toBe("auto");
  });
});

describe("CORS config - input parsing", () => {
  test("parses an inline JSON string", () => {
    const parsed = parseCorsConfigInput('{"credentials": true, "maxAge": 60}');
    expect(parsed.credentials).toBe(true);
    expect(parsed.maxAge).toBe(60);
  });

  test("parses a JSON file path", () => {
    const dir = mkdtempSync(join(tmpdir(), "maahes-cors-"));
    const file = join(dir, "cors.json");
    writeFileSync(file, '{"origin": ["https://a.example.com"], "methods": ["GET", "POST"]}');
    const parsed = parseCorsConfigInput(file);
    expect(parsed.origin).toEqual(["https://a.example.com"]);
    expect(parsed.methods).toEqual(["GET", "POST"]);
  });

  test("unwraps a {'cors': ...} wrapper from JSON strings and files", () => {
    const parsed = parseCorsConfigInput('{"cors": {"credentials": true}}');
    expect(parsed.credentials).toBe(true);

    const dir = mkdtempSync(join(tmpdir(), "maahes-cors-"));
    const file = join(dir, "config.json");
    writeFileSync(file, '{"cors": {"maxAge": 30}}');
    expect(parseCorsConfigInput(file).maxAge).toBe(30);
  });

  test("rejects JSON without an object at the root", () => {
    expect(() => parseCorsConfigInput("[1, 2, 3]")).toThrow(CorsOptionsError);
    expect(() => parseCorsConfigInput("42")).toThrow(CorsOptionsError);
    expect(() => parseCorsConfigInput("missing-file.json")).toThrow(Error);
  });

  test("rejects array configs passed as objects", () => {
    expect(() => parseCorsConfigInput(["a"] as unknown as object)).toThrow(CorsOptionsError);
  });
});

describe("CORS config - validation", () => {
  const rejects = (config: Record<string, unknown>): void => {
    expect(() => resolveConfig(config)).toThrow(CorsOptionsError);
  };

  test("rejects unknown matchMode and preflight values", () => {
    rejects({ matchMode: "fuzzy" });
    rejects({ preflight: "sometimes" });
  });

  test("rejects non-boolean credentials/allowPrivateNetwork/allowNullOrigin", () => {
    rejects({ credentials: "yes" as unknown as boolean });
    rejects({ allowPrivateNetwork: 1 as unknown as boolean });
    rejects({ allowNullOrigin: null as unknown as boolean });
  });

  test("rejects invalid status codes and maxAge", () => {
    rejects({ optionsSuccessStatus: 199 });
    rejects({ optionsSuccessStatus: 600 });
    rejects({ optionsSuccessStatus: 204.5 });
    rejects({ failureStatus: 99 });
    rejects({ maxAge: -1 });
    rejects({ maxAge: 1.5 });
  });

  test("rejects empty methods arrays and whitespace methods", () => {
    rejects({ methods: [] });
    rejects({ methods: ["GET", " " ]});
  });

  test("rejects malformed allowedHeaders/exposedHeaders/origin/allowlist", () => {
    rejects({ allowedHeaders: "x-token" as unknown as string[] });
    rejects({ exposedHeaders: "x-debug" as unknown as string[] });
    rejects({ origin: 42 as unknown as string });
    rejects({ allowlist: "https://a.example.com" as unknown as string[] });
  });

  test("rejects unknown presets", () => {
    rejects({ preset: "nestjs" });
  });

  test("accepts RegExp, rule arrays and callback origins", () => {
    expect(() => resolveConfig({ origin: /^https:\/\/[a-z]+\.example\.com$/ })).not.toThrow();
    expect(() =>
      resolveConfig({ origin: [{ pattern: "https://a.example.com", credentials: true }] })
    ).not.toThrow();
    expect(() => resolveConfig({ origin: (_o, cb) => cb(null, true) })).not.toThrow();
  });
});

describe("CORS config - allowlist folding", () => {
  test("allowlist alone becomes the origin list", () => {
    const resolved = resolveConfig({ allowlist: ["https://a.example.com"] });
    expect(resolved.allowlist).toBeUndefined();
    expect(resolved.origin).toEqual(["https://a.example.com"]);
  });

  test("allowlist merges with an existing origin list without duplicates semantics", () => {
    const resolved = resolveConfig({
      origin: ["https://a.example.com"],
      allowlist: [{ pattern: "https://b.example.com", credentials: true }],
    });
    expect(resolved.origin).toHaveLength(2);
    expect(resolved.allowlist).toBeUndefined();
  });

  test("allowlist replaces the wildcard default when no origin is given", () => {
    const resolved = resolveConfig({ allowlist: ["https://*.example.com"] });
    expect(resolved.origin).toEqual(["https://*.example.com"]);
  });
});