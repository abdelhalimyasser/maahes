import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Cors, CorsOptionsError } from "../../src/cors/index";

describe("Cors() - factory surface", () => {
  test("no-argument construction uses the secure defaults", () => {
    const cors = Cors();
    expect(cors.process({ method: "GET", headers: { origin: "https://x.example.com" } }).allowed).toBe(true);
  });

  test("accepts config objects, JSON strings and JSON files", () => {
    expect(Cors({ credentials: true }).process({ method: "GET", headers: { origin: "https://a.example.com" } }).allowed).toBe(true);

    const fromJson = Cors('{"origin": ["https://a.example.com"]}');
    expect(fromJson.process({ method: "GET", headers: { origin: "https://a.example.com" } }).allowed).toBe(true);
    expect(fromJson.process({ method: "GET", headers: { origin: "https://b.example.com" } }).allowed).toBe(false);

    const dir = mkdtempSync(join(tmpdir(), "maahes-cors-factory-"));
    const file = join(dir, "cors.json");
    writeFileSync(file, '{"cors": {"origin": ["https://file.example.com"]}}');
    const fromFile = Cors(file);
    expect(fromFile.process({ method: "GET", headers: { origin: "https://file.example.com" } }).allowed).toBe(true);
  });

  test("invalid options throw CorsOptionsError at construction", () => {
    expect(() => Cors({ maxAge: -5 })).toThrow(CorsOptionsError);
    expect(() => Cors('{"preflight": "sometimes"}')).toThrow(CorsOptionsError);
  });

  test("the 'express' preset answers plain OPTIONS like npm cors", () => {
    const cors = Cors({ preset: "express", origin: ["https://app.example.com"] });
    const result = cors.process({
      method: "OPTIONS",
      headers: { origin: "https://app.example.com" },
    });
    expect(result.preflight).toBe(true);
    expect(result.allowed).toBe(true);
  });

  test("isPreflight delegates to the configured mode", () => {
    const auto = Cors();
    expect(auto.isPreflight({ method: "OPTIONS", headers: { "access-control-request-method": "GET" } })).toBe(true);
    expect(auto.isPreflight({ method: "OPTIONS", headers: {} })).toBe(false);

    const always = Cors({ preset: "express" });
    expect(always.isPreflight({ method: "OPTIONS", headers: {} })).toBe(true);

    const never = Cors({ preflight: "never" });
    expect(never.isPreflight({ method: "OPTIONS", headers: { "access-control-request-method": "GET" } })).toBe(false);
  });

  test("allowedOrigin resolves an origin to itself or null", () => {
    const cors = Cors({ origin: ["https://app.example.com"] });
    expect(cors.allowedOrigin("https://app.example.com")).toBe("https://app.example.com");
    expect(cors.allowedOrigin("https://evil.com")).toBeNull();
    expect(cors.allowedOrigin(undefined)).toBeNull();

    const anything = Cors();
    expect(anything.allowedOrigin("https://anything.dev")).toBe("https://anything.dev");
  });
});

describe("Cors() - sync/async split", () => {
  test("process() throws for callback-based origins; processAsync() works", async () => {
    const cors = Cors({ origin: (_origin, callback) => callback(null, true) });
    expect(() => cors.process({ method: "GET", headers: { origin: "https://a.example.com" } })).toThrow(
      CorsOptionsError
    );

    const result = await cors.processAsync({
      method: "GET",
      headers: { origin: "https://a.example.com" },
    });
    expect(result.allowed).toBe(true);
    expect(result.headers["Access-Control-Allow-Origin"]).toBe("https://a.example.com");
  });

  test("processAsync rejects when the callback reports an error", async () => {
    const cors = Cors({
      origin: (_origin, callback) => callback(new Error("resolution failed")),
    });
    await expect(
      cors.processAsync({ method: "GET", headers: { origin: "https://a.example.com" } })
    ).rejects.toThrow("resolution failed");
  });

  test("callback denials become blocked results with statusCode", async () => {
    const cors = Cors({
      origin: (_origin, callback) => callback(null, false),
      failureStatus: 403,
    });
    const result = await cors.processAsync({
      method: "OPTIONS",
      headers: { origin: "https://a.example.com", "access-control-request-method": "GET" },
    });
    expect(result.allowed).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.preflight).toBe(true);
  });
});

describe("Cors() - determinism", () => {
  test("two modules with the same config produce identical outputs", () => {
    const a = Cors({ origin: ["https://a.example.com"], credentials: true, maxAge: 300 });
    const b = Cors({ origin: ["https://a.example.com"], credentials: true, maxAge: 300 });

    const input = {
      method: "OPTIONS",
      headers: {
        origin: "https://a.example.com",
        "access-control-request-method": "PUT",
        "access-control-request-headers": "x-token, content-type",
      },
    };
    expect(a.process(input)).toEqual(b.process(input));
  });

  test("module instances are share-safe across concurrent calls", async () => {
    const cors = Cors({ origin: ["https://a.example.com"], credentials: true });
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        cors.processAsync({
          method: "GET",
          headers: { origin: i % 2 === 0 ? "https://a.example.com" : "https://b.example.com" },
        })
      )
    );
    const allowed = results.filter((r) => r.allowed).length;
    expect(allowed).toBe(25);
  });
});