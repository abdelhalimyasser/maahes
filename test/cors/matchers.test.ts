import { describe, expect, test } from "bun:test";
import {
  compileEntry,
  compileGlob,
  compileOrigin,
  normalizeOrigin,
  resolveOrigin,
} from "../../src/cors/matchers";

describe("CORS matchers - compileGlob", () => {
  test("a bare * matches everything", () => {
    const match = compileGlob("*");
    expect(match("https://anything.example.com")).toBe(true);
    expect(match("null")).toBe(true);
  });

  test("validates scheme and host boundaries", () => {
    const match = compileGlob("https://*.example.com");
    expect(match("https://sub.example.com")).toBe(true);
    expect(match("https://a.b.example.com")).toBe(true);
    expect(match("http://sub.example.com")).toBe(false);
    expect(match("https://example.com")).toBe(false);
    expect(match("https://sub.example.com.evil.io")).toBe(false);
    expect(match("https://evil.com/https://example.com")).toBe(false);
  });

  test("question marks match a single character", () => {
    const match = compileGlob("https://a?b.example.com");
    expect(match("https://acb.example.com")).toBe(true);
    expect(match("https://axb.example.com")).toBe(true);
    expect(match("https://a-cb.example.com")).toBe(false);
  });

  test("rejects the literal pattern as a regex when used exactly", () => {
    const match = compileGlob("https://example.com");
    expect(match("https://example.com")).toBe(true);
    expect(match("https://zexample.com")).toBe(false);
  });
});

describe("CORS matchers - compileEntry", () => {
  test("exact mode compares equality", () => {
    const match = compileEntry("https://example.com", "exact");
    expect(match("https://example.com")).toBe(true);
    expect(match("https://example.com:8443")).toBe(false);
  });

  test("auto mode detects wildcards and falls back to exact", () => {
    expect(compileEntry("https://*.example.com", "auto")("https://x.example.com")).toBe(true);
    expect(compileEntry("https://example.com", "auto")("https://example.com")).toBe(true);
    expect(compileEntry("https://example.com", "auto")("https://example.org")).toBe(false);
  });

  test("regex mode treats strings as RegExp sources and matches RegExp instances", () => {
    const source = compileEntry("^https://[a-z]+\\.example\\.com$", "regex");
    expect(source("https://shop.example.com")).toBe(true);
    expect(source("https://SHOP.example.com")).toBe(false);

    const instance = compileEntry(/^https:\/\/[a-z]+\.example\.com$/i, "auto");
    expect(instance("https://SHOP.example.com")).toBe(true);
  });

  test("normalizes scheme and host case for string rules", () => {
    const matcher = compileOrigin({ origin: "HTTPS://Example.COM" });
    expect(resolveOrigin(matcher, "https://example.com").matched).toBe(true);
    expect(resolveOrigin(matcher, "https://example.com.evil.io").matched).toBe(false);
  });

  test("escapes regex metacharacters in glob mode", () => {
    const match = compileGlob("https://example.com/*.html");
    expect(match("https://example.com/page.html")).toBe(true);
    expect(match("https://example.com/x/page.html")).toBe(false);
  });
});

describe("CORS matchers - compileOrigin", () => {
  test("wildcard config compiles to the 'any' matcher", () => {
    const matcher = compileOrigin({ origin: "*" });
    expect(matcher.kind).toBe("any");
    expect(resolveOrigin(matcher, "https://x.example.com").matched).toBe(true);
  });

  test("exact string list requires identity (auto mode)", () => {
    const matcher = compileOrigin({ origin: ["https://app.example.com"] });
    expect(resolveOrigin(matcher, "https://app.example.com").matched).toBe(true);
    expect(resolveOrigin(matcher, "https://app.example.com.evil.io").matched).toBe(false);
  });

  test("per-origin rules carry their credentials flag", () => {
    const matcher = compileOrigin({
      origin: [
        { pattern: "https://public.example.com", credentials: true },
        "https://plain.example.com",
      ],
    });
    const publicMatch = resolveOrigin(matcher, "https://public.example.com");
    expect(publicMatch.matched).toBe(true);
    expect(publicMatch.credentials).toBe(true);

    const plainMatch = resolveOrigin(matcher, "https://plain.example.com");
    expect(plainMatch.matched).toBe(true);
    expect(plainMatch.credentials).toBeUndefined();
  });

  test("allowNullOrigin admits the literal 'null' origin", () => {
    const matcher = compileOrigin({ origin: ["https://app.example.com"], allowNullOrigin: true });
    expect(resolveOrigin(matcher, "null").matched).toBe(true);

    const strict = compileOrigin({ origin: ["https://app.example.com"] });
    expect(resolveOrigin(strict, "null").matched).toBe(false);
  });

  test("credentialed rules win over broader plain patterns", () => {
    const matcher = compileOrigin({
      origin: [
        "https://*.example.com",
        { pattern: "https://admin.example.com", credentials: true },
      ],
      credentials: false,
    });
    const admin = resolveOrigin(matcher, "https://admin.example.com");
    expect(admin.matched).toBe(true);
    expect(admin.credentials).toBe(true);

    const other = resolveOrigin(matcher, "https://other.example.com");
    expect(other.matched).toBe(true);
    expect(other.credentials).toBeUndefined();
  });

  test("callback configs compile to the callback matcher", () => {
    const matcher = compileOrigin({ origin: (_o, cb) => cb(null, true) });
    expect(matcher.kind).toBe("callback");
  });

  test("RegExp config compiles to the regex matcher", () => {
    const matcher = compileOrigin({ origin: /^https:\/\/[a-z]+\.example\.com$/ });
    expect(matcher.kind).toBe("regex");
    expect(resolveOrigin(matcher, "https://api.example.com").matched).toBe(true);
    expect(resolveOrigin(matcher, "https://api.example.org").matched).toBe(false);
  });
});

describe("CORS matchers - normalizeOrigin", () => {
  test("lowercases scheme and host but preserves path", () => {
    expect(normalizeOrigin("HTTPS://Example.COM/Path?q=1")).toBe("https://example.com/Path?q=1");
  });

  test("lowercases scheme-less values entirely", () => {
    expect(normalizeOrigin("Example.COM")).toBe("example.com");
  });
});