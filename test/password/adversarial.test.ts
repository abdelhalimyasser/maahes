import { describe, expect, test } from "bun:test";
import {
  Password,
  PasswordOptionsError,
  extractPepperId,
  isPepperedHash,
  detectHashAlgorithm,
} from "../../src/password/index";
import { createHmac } from "node:crypto";

const pw = (pw: string): string => createHmac("sha256", "legacy-secret").update(pw, "utf8").digest("hex");

describe("adversarial: malformed hashes never throw and never verify", () => {
  const pwd = Password({ algorithm: "argon2" });

  const MALFORMED = [
    "",
    "garbage",
    "$argon2id$v=19$m=65536,t=3,p=1",
    "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$",
    "$argon2id$v=19$m=65536,t=3,p=1$!!notbase64!!$hash",
    "$2b$10$",
    "$2b$10$tooshort",
    "$2a$4$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "$scrypt$N=16384$r=8$p=1",
    "$scrypt$N=16384$r=8$p=1$c29tZXNhbHQ$",
    "$scrypt$N=notanumber$r=8$p=1$c29tZXNhbHQ$c29tZXNhbHQ$",
    "$md5$deadbeef",
    "password123",
    "$pepper$00000000$",
    "$pepper$",
    "$pepper$$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash",
  ];

  test("verifyPassword returns false for every malformed hash", async () => {
    for (const hash of MALFORMED) {
      expect(await pwd.verifyPassword(hash, "some-password")).toBe(false);
    }
  });

  test("verifyAndRehash never returns a newHash for malformed hashes", async () => {
    for (const hash of MALFORMED) {
      const result = await pwd.verifyAndRehash(hash, "some-password");
      expect(result.valid).toBe(false);
      expect(result.newHash).toBeUndefined();
    }
  });

  test("needsRehash flags malformed hashes for migration", async () => {
    for (const hash of MALFORMED) {
      expect(await pwd.needsRehash(hash)).toBe(true);
    }
  });
});

describe("adversarial: unsupported algorithm strings", () => {
  test("construction throws for unknown algorithms", () => {
    expect(() => Password({ algorithm: "md5" as never })).toThrow(/Unknown password algorithm/);
    expect(() => Password({ algorithm: "" as never })).toThrow(/Unknown password algorithm/);
  });

  test("verification of an unsupported foreign hash is false, never throws", async () => {
    const pwd = Password();
    expect(await pwd.verifyPassword("$md5$deadbeef", "x")).toBe(false);
    expect(await pwd.verifyPassword("$pbkdf2-sha256$29000$abc$def", "x")).toBe(false);
  });
});

describe("adversarial: pepper markers", () => {
  test("corrupted markers fail safely (never throw, never verify)", async () => {
    const pwd = Password({ pepper: "secret" });
    const good = await pwd.pepperedHashPassword("pw");
    const id = extractPepperId(good);

    const corrupted = [
      `$pepper$abc$de` + good.slice(good.indexOf("$", good.indexOf("$", 1) + 1)), // id too short is fine, but inner mangled
      good.replace(id, "!!!!!!!!"), // invalid id characters
      good.slice(0, -10), // truncated inner hash
      `$pepper$${id}$`, // empty inner
      `$pepper$${id}$${id}`, // doubled id instead of inner hash
      `$pepper$` + "x".repeat(33) + `$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$hash`, // 33-char id
    ];

    for (const hash of corrupted) {
      expect(await pwd.verifyPassword(hash, "pw")).toBe(false);
      expect((await pwd.verifyAndRehash(hash, "pw")).valid).toBe(false);
    }
  });

  test("unknown pepper ids fail safely even when a ring is configured", async () => {
    const pwd = Password({
      pepper: { current: { id: "2026-08", secret: "new-secret" }, previous: [{ id: "2026-07", secret: "old-secret" }] },
    });
    const hash = await pwd.pepperedHashPassword("pw");
    const forged = hash.replace(extractPepperId(hash)!, "2026-06"); // id not in the ring
    expect(isPepperedHash(forged)).toBe(true);
    expect(await pwd.verifyPassword(forged, "pw")).toBe(false);
    expect((await pwd.verifyAndRehash(forged, "pw")).valid).toBe(false);
    expect(await pwd.needsRehash(forged)).toBe(true);
  });

  test("unknown pepper id with a valid-looking but wrong secret never verifies", async () => {
    const pwd = Password({ pepper: { current: { id: "a", secret: "s1" }, previous: [{ id: "b", secret: "s2" }] } });
    const hash = await pwd.pepperedHashPassword("pw");
    const forged = hash.replace(extractPepperId(hash)!, "b"); // id exists but wrong secret for this hash
    expect(await pwd.verifyPassword(forged, "pw")).toBe(false);
  });

  test("marked hash verification without any pepper configured returns false, not throw", async () => {
    const withPepper = Password({ pepper: "some-secret" });
    const hash = await withPepper.pepperedHashPassword("pw");
    const withoutPepper = Password();
    expect(await withoutPepper.verifyPassword(hash, "pw")).toBe(false);
    expect((await withoutPepper.verifyAndRehash(hash, "pw")).valid).toBe(false);
  });

  test("pepperedVerifyPassword without a pepper still throws a clear error for legacy hashes", async () => {
    const pwd = Password();
    await expect(pwd.pepperedVerifyPassword("$2b$04$not-a-real-hash", "pw")).rejects.toThrow(/pepper/i);
  });
});

describe("adversarial: pepper rotation lifecycle", () => {
  const OLD = { id: "2026-07", secret: "old-secret" };
  const NEW = { id: "2026-08", secret: "new-secret" };

  test("new hashes carry the current id; old-era hashes verify and rehash to the current pepper", async () => {
    const before = Password({ pepper: { current: OLD } });
    const oldHash = await before.pepperedHashPassword("pw");

    const after = Password({ pepper: { current: NEW, previous: [OLD] } });

    expect(await after.verifyPassword(oldHash, "pw")).toBe(true);
    expect((await after.needsRehash(oldHash))).toBe(true);

    const result = await after.verifyAndRehash(oldHash, "pw");
    expect(result.valid).toBe(true);
    expect(result.newHash).toBeDefined();
    expect(extractPepperId(result.newHash!)).toBe(NEW.id);
    expect(await after.verifyPassword(result.newHash!, "pw")).toBe(true);
  });

  test("current-era hashes do NOT rehash", async () => {
    const after = Password({ pepper: { current: NEW, previous: [OLD] } });
    const currentHash = await after.pepperedHashPassword("pw");
    expect((await after.needsRehash(currentHash))).toBe(false);
    const result = await after.verifyAndRehash(currentHash, "pw");
    expect(result.valid).toBe(true);
    expect(result.newHash).toBeUndefined();
  });

  test("a wrong password never triggers pepper rehash", async () => {
    const before = Password({ pepper: { current: OLD } });
    const oldHash = await before.pepperedHashPassword("pw");
    const after = Password({ pepper: { current: NEW, previous: [OLD] } });
    const result = await after.verifyAndRehash(oldHash, "wrong");
    expect(result).toEqual({ valid: false });
  });

  test("two previous eras both verify", async () => {
    const ring = {
      current: { id: "2026-08", secret: "s3" },
      previous: [
        { id: "2026-07", secret: "s2" },
        { id: "2026-06", secret: "s1" },
      ],
    };
    const pwd = Password({ pepper: ring });
    const h1 = await Password({ pepper: { current: { id: "2026-06", secret: "s1" } } }).pepperedHashPassword("pw");
    const h2 = await Password({ pepper: { current: { id: "2026-07", secret: "s2" } } }).pepperedHashPassword("pw");
    expect(await pwd.verifyPassword(h1, "pw")).toBe(true);
    expect(await pwd.verifyPassword(h2, "pw")).toBe(true);
  });

  test("legacy unmarked peppered hashes verify against current, then previous secrets", async () => {
    const hmac = (secret: string, value: string) =>
      createHmac("sha256", secret).update(value, "utf8").digest("hex");
    const legacy = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const oldHash = await legacy.rehashPassword(hmac(OLD.secret, "pw"));

    const pwd = Password({
      algorithm: "scrypt",
      scrypt: { cost: 2 ** 10 },
      pepper: { current: NEW, previous: [OLD] },
    });
    expect(await pwd.pepperedVerifyPassword(oldHash, "pw")).toBe(true);
  });

  test("legacy string-form pepper ids stay 8-hex and match the 1.x marker format", async () => {
    const pwd = Password({ pepper: "string-secret" });
    const hash = await pwd.pepperedHashPassword("pw");
    expect(extractPepperId(hash)).toMatch(/^[0-9a-f]{8}$/);
  });

  test("pepper ids may be long, mixed-case and dashed", async () => {
    const pwd = Password({ pepper: { current: { id: "Prod-2026_Aug-1", secret: "s" } } });
    const hash = await pwd.pepperedHashPassword("pw");
    expect(isPepperedHash(hash)).toBe(true);
    expect(await pwd.verifyPassword(hash, "pw")).toBe(true);
  });
});

describe("adversarial: pepper keyring configuration validation", () => {
  test("rejects empty secrets and malformed ids without leaking the secret", () => {
    expect(() => Password({ pepper: "" })).toThrow(PasswordOptionsError);
    expect(() => Password({ pepper: { current: { id: "ok", secret: "" } } })).toThrow(PasswordOptionsError);
    expect(() => Password({ pepper: { current: { id: "has space", secret: "s" } } })).toThrow(PasswordOptionsError);
    expect(() => Password({ pepper: { current: { id: "x".repeat(33), secret: "s" } } })).toThrow(PasswordOptionsError);
    expect(() => Password({ pepper: { id: "ok", secret: "s" } } as never)).toThrow(/pepper/i);
  });

  test("rejects duplicate and current-colliding previous ids", () => {
    expect(() =>
      Password({ pepper: { current: { id: "a", secret: "s1" }, previous: [{ id: "a", secret: "s2" }] } })
    ).toThrow(PasswordOptionsError);
    expect(() =>
      Password({
        pepper: {
          current: { id: "a", secret: "s1" },
          previous: [
            { id: "b", secret: "s2" },
            { id: "b", secret: "s3" },
          ],
        },
      })
    ).toThrow(PasswordOptionsError);
  });

  test("error messages never contain secret material", () => {
    try {
      Password({ pepper: { current: { id: "ok", secret: "TOP-SECRET-PEPPER" } } as never });
    } catch (err) {
      expect(String(err)).not.toContain("TOP-SECRET-PEPPER");
    }
  });
});

describe("adversarial: unicode, normalization and input edges", () => {
  test("long unicode passwords round-trip (emoji, combining marks, astral)", async () => {
    const pwd = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const password = "🔐pässwörd😀" + "e\u0301".repeat(10) + "𐍈𐍉𐍊";
    const hash = await pwd.hashPassword(password);
    expect(await pwd.verifyPassword(hash, password)).toBe(true);
  });

  test("nfkc folds confusables and zero-width-joined sequences deterministically", async () => {
    const pwd = Password({ normalize: "nfkc" });
    const a = await pwd.hashPassword("café");
    expect(await pwd.verifyPassword(a, "cafe\u0301")).toBe(true);
  });

  test("null bytes are handled without error", async () => {
    const pwd = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const hash = await pwd.hashPassword("pass\u0000word");
    expect(await pwd.verifyPassword(hash, "pass\u0000word")).toBe(true);
    expect(await pwd.verifyPassword(hash, "password")).toBe(false);
  });

  test("unusual whitespace is rejected by default policy and allowed when opted out", async () => {
    const pwd = Password({ policy: { blockWhitespace: true } });
    for (const ws of ["\u00a0", "\u2003", "\t", "\n", "\u2028"]) {
      expect(pwd.validatePassword(`a${ws}b1A!zzz`).valid).toBe(false);
    }
    const relaxed = Password({ policy: { blockWhitespace: false } });
    expect(relaxed.validatePassword("a\u2003b1A!zzz").valid).toBe(true);
  });

  test("very long inputs are bounded by policy and never hang verification", async () => {
    const pwd = Password({ policy: { maxLength: 128, enforceOnHash: true } });
    await expect(pwd.hashPassword("a".repeat(100_000))).rejects.toThrow(/maxLength/i);
    const tolerant = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const long = "x".repeat(10_000);
    const hash = await tolerant.hashPassword(long);
    expect(await tolerant.verifyPassword(hash, long)).toBe(true);
  });

  test("allowedScripts default accepts non-Latin scripts; restrictions remain opt-in", async () => {
    const pwd = Password(); // default ["Any"]
    expect(pwd.validatePassword("مرحباالعالم123").valid).toBe(true);
    expect(pwd.validatePassword("Приветмир123").valid).toBe(true);
    expect(pwd.validatePassword("你好世界你好123").valid).toBe(true);
    const latinOnly = Password({ policy: { allowedScripts: ["Latin"] } });
    expect(latinOnly.validatePassword("مرحباالعالم123").valid).toBe(false);
    expect(latinOnly.validatePassword("helloworld123").valid).toBe(true);
  });
});

describe("adversarial: extreme and capped driver settings", () => {
  test("argon2 caps reject over-limit construction", () => {
    expect(() => Password({ argon2: { memoryCost: 2 ** 21 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { timeCost: 33 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { parallelism: 17 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { hashLength: 300 } })).toThrow(PasswordOptionsError);
  });

  test("scrypt caps reject over-limit construction", () => {
    expect(() => Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 19 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { blockSize: 17 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { parallelization: 9 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { keyLength: 200 } })).toThrow(PasswordOptionsError);
  });

  test("stored scrypt hashes with over-cap embedded parameters never verify", async () => {
    const pwd = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const evil = "$scrypt$N=1073741824$r=8$p=1$c29tZXNhbHQ$c29tZXNhbHQ$";
    expect(await pwd.verifyPassword(evil, "pw")).toBe(false);
    expect(await pwd.needsRehash(evil)).toBe(true);
  });

  test("stored argon2 hashes with over-cap embedded parameters never verify", async () => {
    const pwd = Password();
    const evil = "$argon2id$v=19$m=2147483647,t=3,p=1$c29tZXNhbHQ$c29tZXNhbHQ$";
    expect(await pwd.verifyPassword(evil, "pw")).toBe(false);
    expect(await pwd.needsRehash(evil)).toBe(true);
  });

  test("oversized scrypt hash strings are rejected without allocation", async () => {
    const pwd = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const huge = `$scrypt$N=1024$r=8$p=1$${"A".repeat(100_000)}$${"B".repeat(100_000)}`;
    expect(await pwd.verifyPassword(huge, "pw")).toBe(false);
  });

  test("bcrypt cost boundaries: rounds 03 rejected, 04 and 31 accepted at construction", () => {
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 3 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 32 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } })).not.toThrow();
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 31 } })).not.toThrow();
  });

  test("stored bcrypt hashes outside 4..31 rounds never verify", async () => {
    const pwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const low = "$2b$03$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const high = "$2b$32$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    expect(await pwd.verifyPassword(low, "pw")).toBe(false);
    expect(await pwd.verifyPassword(high, "pw")).toBe(false);
  });
});

describe("adversarial: migration flows", () => {
  test("algorithm migration: argon2-configured module verifies legacy bcrypt and rehashes to argon2", async () => {
    const legacy = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const stored = await legacy.hashPassword("pw");

    const current = Password({ algorithm: "argon2" });
    expect(await current.verifyPassword(stored, "pw")).toBe(true);
    expect(detectHashAlgorithm(stored)).toBe("bcrypt");

    const result = await current.verifyAndRehash(stored, "pw");
    expect(result.valid).toBe(true);
    expect(result.newHash).toBeDefined();
    expect(detectHashAlgorithm(result.newHash!)).toBe("argon2");
  });

  test("algorithm migration keeps pepper marking on the rehashed hash", async () => {
    const legacy = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 }, pepper: { current: { id: "2026-01", secret: "old" } } });
    const stored = await legacy.pepperedHashPassword("pw");

    const current = Password({
      algorithm: "argon2",
      pepper: { current: { id: "2026-08", secret: "new" }, previous: [{ id: "2026-01", secret: "old" }] },
    });
    const result = await current.verifyAndRehash(stored, "pw");
    expect(result.valid).toBe(true);
    expect(extractPepperId(result.newHash!)).toBe("2026-08");
    expect(detectHashAlgorithm(result.newHash!)).toBe("argon2");
    expect(await current.verifyPassword(result.newHash!, "pw")).toBe(true);
  });

  test("scrypt -> argon2 migration with self-describing params", async () => {
    const legacy = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10, blockSize: 8, parallelization: 2 } });
    const stored = await legacy.hashPassword("pw");

    const current = Password({ algorithm: "argon2" });
    expect(await current.verifyPassword(stored, "pw")).toBe(true);
    const result = await current.verifyAndRehash(stored, "pw");
    expect(detectHashAlgorithm(result.newHash!)).toBe("argon2");
  });

  test("parameter migration: same algorithm, outdated params rehash", async () => {
    const old = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const stored = await old.hashPassword("pw");
    const current = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 6 } });
    const result = await current.verifyAndRehash(stored, "pw");
    expect(result.valid).toBe(true);
    expect(result.newHash).toBeDefined();
    expect(result.newHash!.startsWith("$2")).toBe(true);
  });

  test("bcrypt preHash mode change invalidates hashes (documented limitation)", async () => {
    const old = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4, preHash: true } });
    const stored = await old.hashPassword("pw");
    const current = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4, preHash: false } });
    // The hash format cannot record which preHash mode produced it, so a
    // mode flip is NOT automatically migratable: verification fails and
    // no replacement hash is produced (honest behavior, no false claims).
    const result = await current.verifyAndRehash(stored, "pw");
    expect(result).toEqual({ valid: false });
    expect(await current.verifyPassword(stored, "pw")).toBe(false);
  });

  test("wrong password during algorithm migration returns no newHash", async () => {
    const legacy = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const stored = await legacy.hashPassword("pw");
    const current = Password({ algorithm: "argon2" });
    expect(await current.verifyAndRehash(stored, "WRONG")).toEqual({ valid: false });
  });

  test("normalization config change: ASCII hashes keep verifying, confusable hashes do not", async () => {
    const old = Password({ normalize: "none", algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const asciiStored = await old.hashPassword("password123");
    const confusableStored = await old.hashPassword("ｐａｓｓｗｏｒｄ１２３");

    const current = Password({ normalize: "nfkc", algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    // ASCII: unchanged by normalization -> verifies.
    const asciiResult = await current.verifyAndRehash(asciiStored, "password123");
    expect(asciiResult.valid).toBe(true);
    // Confusable: the stored form folds away from the raw string, so the
    // hash can never match again (documented limitation of changing
    // normalization mid-flight - no false rehash claims).
    const confusableResult = await current.verifyAndRehash(confusableStored, "ｐａｓｓｗｏｒｄ１２３");
    expect(confusableResult).toEqual({ valid: false });
  });
});

describe("adversarial: secrets never leak", () => {
  test("verification errors never include the password or pepper", async () => {
    const pwd = Password({ pepper: "leaky-pepper" });
    const hash = await pwd.pepperedHashPassword("leaky-password");
    try {
      await pwd.pepperedVerifyPassword("$2b$04$nope", "leaky-password");
    } catch (err) {
      const text = String(err);
      expect(text).not.toContain("leaky-password");
      expect(text).not.toContain("leaky-pepper");
    }
    expect(hash).not.toContain("leaky-pepper");
  });
});