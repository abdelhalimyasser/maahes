import { describe, expect, test } from "bun:test";
import { Password, detectHashAlgorithm, isPepperedHash, stripPepperMarker } from "../../src/password/index";

describe("detectHashAlgorithm", () => {
  test("detects argon2 hashes (all variants)", () => {
    expect(detectHashAlgorithm("$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash")).toBe("argon2");
    expect(detectHashAlgorithm("$argon2i$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash")).toBe("argon2");
    expect(detectHashAlgorithm("$argon2d$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash")).toBe("argon2");
  });

  test("detects bcrypt hashes (all variants)", () => {
    expect(detectHashAlgorithm("$2a$10$abcdefghijklmnopqrstuvwyz0123456789")).toBe("bcrypt");
    expect(detectHashAlgorithm("$2b$10$abcdefghijklmnopqrstuvwyz0123456789")).toBe("bcrypt");
    expect(detectHashAlgorithm("$2y$10$abcdefghijklmnopqrstuvwyz0123456789")).toBe("bcrypt");
  });

  test("detects scrypt hashes", () => {
    expect(detectHashAlgorithm("$scrypt$N=16384$r=8$p=1$c29tZXNhbHQ$hash")).toBe("scrypt");
  });

  test("returns null for unrecognized formats", () => {
    expect(detectHashAlgorithm("garbage")).toBeNull();
    expect(detectHashAlgorithm("")).toBeNull();
    expect(detectHashAlgorithm("$md5$abc")).toBeNull();
  });

  test("detects through the pepper marker", async () => {
    const pwd = Password({ pepper: "s3cret", algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await pwd.pepperedHashPassword("my-password");

    expect(isPepperedHash(hash)).toBe(true);
    expect(detectHashAlgorithm(hash)).toBe("bcrypt");
  });

  test("stripPepperMarker removes the wrapper and leaves plain hashes untouched", async () => {
    const pwd = Password({ pepper: "s3cret", algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const marked = await pwd.pepperedHashPassword("my-password");
    const plain = await pwd.hashPassword("my-password");

    const inner = stripPepperMarker(marked);
    expect(inner.startsWith("$2")).toBe(true);
    expect(stripPepperMarker(plain)).toBe(plain);
  });

  test("driver output round-trips through detection", async () => {
    for (const algorithm of ["argon2", "bcrypt", "scrypt"] as const) {
      const pwd = Password({ algorithm, scrypt: { cost: 2 ** 10 }, bcrypt: { saltRounds: 4 } });
      const hash = await pwd.hashPassword("round-trip-me");
      expect(detectHashAlgorithm(hash)).toBe(algorithm);
    }
  });
});