import { describe, expect, test } from "bun:test";
import { Password, PasswordPolicyError } from "../../src/password/index";

describe("Password() - defaults", () => {
  test("works end-to-end with no config at all", async () => {
    const pwd = Password();
    const hash = await pwd.hashPassword("my-secret-password");

    expect(await pwd.verifyPassword(hash, "my-secret-password")).toBe(true);
    expect(await pwd.verifyPassword(hash, "wrong-password")).toBe(false);
  });
});

describe("Password() - algorithm selection", () => {
  test("bcrypt algorithm works end-to-end", async () => {
    const pwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await pwd.hashPassword("my-secret-password");

    expect(await pwd.verifyPassword(hash, "my-secret-password")).toBe(true);
  });

  test("scrypt algorithm works end-to-end", async () => {
    const pwd = Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10 } });
    const hash = await pwd.hashPassword("my-secret-password");

    expect(await pwd.verifyPassword(hash, "my-secret-password")).toBe(true);
  });

  test("unknown algorithm throws immediately", () => {
    expect(() => Password({ algorithm: "md5" as any })).toThrow();
  });
});

describe("Password() - config input formats", () => {
  test("accepts a raw JSON string", async () => {
    const pwd = Password('{"algorithm":"bcrypt","bcrypt":{"saltRounds":4}}');
    const hash = await pwd.hashPassword("test");
    expect(await pwd.verifyPassword(hash, "test")).toBe(true);
  });

  test("missing fields fall back to defaults (deep merge)", async () => {
    // only overriding timeCost - memoryCost/parallelism should still come from defaults
    const pwd = Password({ argon2: { timeCost: 2 } });
    const hash = await pwd.hashPassword("test");
    expect(await pwd.verifyPassword(hash, "test")).toBe(true);
  });
});

describe("Password() - policy enforcement", () => {
  test("validatePassword() reports violations without throwing", () => {
    const pwd = Password({ policy: { minLength: 12 } });
    const result = pwd.validatePassword("short1");

    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("minLength");
  });

  test("hashPassword() does NOT throw on a bad password when enforceOnHash is false", async () => {
    const pwd = Password({ policy: { minLength: 12, enforceOnHash: false } });
    await expect(pwd.hashPassword("short1")).resolves.toBeString();
  });

  test("hashPassword() throws PasswordPolicyError when enforceOnHash is true", async () => {
    const pwd = Password({ policy: { minLength: 12, enforceOnHash: true } });
    await expect(pwd.hashPassword("short1")).rejects.toBeInstanceOf(PasswordPolicyError);
  });

  test("rehashPassword() is never policy-checked, even with enforceOnHash true", async () => {
    // simulates re-hashing an already-accepted password during login
    const pwd = Password({ policy: { minLength: 50, enforceOnHash: true } });
    await expect(pwd.rehashPassword("short")).resolves.toBeString();
  });

  test("hashPassword() throws when a custom rule fails under enforceOnHash", async () => {
    const pwd = Password({
      policy: {
        enforceOnHash: true,
        customRules: [{ rule: "noSequential", test: (pwd) => !/(.)\1{2,}/.test(pwd) }],
      },
    });
    await expect(pwd.hashPassword("abccc123")).rejects.toBeInstanceOf(PasswordPolicyError);
  });
});

describe("Password() - pepper", () => {
  test("pepperedHashPassword/pepperedVerifyPassword round-trip correctly", async () => {
    const pwd = Password({ pepper: "test-pepper-secret" });
    const hash = await pwd.pepperedHashPassword("my-password");

    expect(await pwd.pepperedVerifyPassword(hash, "my-password")).toBe(true);
    expect(await pwd.pepperedVerifyPassword(hash, "wrong-password")).toBe(false);
  });

  test("peppered hashes carry the $pepper$ marker", async () => {
    const pwd = Password({ pepper: "test-pepper-secret" });
    const hash = await pwd.pepperedHashPassword("my-password");

    expect(hash).toMatch(/^\$pepper\$[0-9a-f]{8}\$/);
  });

  test("verifyPassword() auto-detects the pepper marker and verifies with the configured pepper", async () => {
    const pwd = Password({ pepper: "test-pepper-secret" });
    const hash = await pwd.pepperedHashPassword("my-password");

    expect(await pwd.verifyPassword(hash, "my-password")).toBe(true);
    expect(await pwd.verifyPassword(hash, "wrong-password")).toBe(false);
  });

  test("needsRehash() handles pepper-marked hashes transparently", async () => {
    const pwd = Password({ pepper: "test-pepper-secret", algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await pwd.pepperedHashPassword("my-password");

    expect(await pwd.needsRehash(hash)).toBe(false);

    const stricter = Password({ pepper: "test-pepper-secret", algorithm: "bcrypt", bcrypt: { saltRounds: 6 } });
    expect(await stricter.needsRehash(hash)).toBe(true);
  });

  test("a peppered hash does NOT verify with a DIFFERENT pepper", async () => {
    const pwdA = Password({ pepper: "pepper-a" });
    const pwdB = Password({ pepper: "pepper-b" });
    const hash = await pwdA.pepperedHashPassword("my-password");

    expect(await pwdB.verifyPassword(hash, "my-password")).toBe(false);
  });

  test("pepperedHashPassword throws a clear error when no pepper is configured", async () => {
    const pwd = Password(); // no pepper, and assumes PASSWORD_PEPPER env var is unset in test env
    await expect(pwd.pepperedHashPassword("my-password")).rejects.toThrow(/pepper/i);
  });
});

describe("Password() - normalization", () => {
  test("normalize 'nfkc' folds full-width characters into ASCII at hash time", async () => {
    const pwd = Password({ normalize: "nfkc", policy: { minLength: 8, enforceOnHash: true } });
    const hash = await pwd.hashPassword("ｐａｓｓｗｏｒｄ１２３");

    // the NFKC-folded form verifies
    expect(await pwd.verifyPassword(hash, "password123")).toBe(true);
    // the raw full-width form also verifies (it folds to the same string)
    expect(await pwd.verifyPassword(hash, "ｐａｓｓｗｏｒｄ１２３")).toBe(true);
  });

  test("without normalization, full-width and ASCII forms are distinct", async () => {
    const pwd = Password();
    const hash = await pwd.hashPassword("password123");

    expect(await pwd.verifyPassword(hash, "ｐａｓｓｗｏｒｄ１２３")).toBe(false);
  });

  test("with nfkc, validation sees the folded password", () => {
    const pwd = Password({ normalize: "nfkc", policy: { minLength: 8 } });
    // "ｐａｓｓ１" folds to "pass1" (5 chars) - fails; "ｐａｓｓｗｏｒｄ" folds to 8 chars - passes
    expect(pwd.validatePassword("ｐａｓｓ１").valid).toBe(false);
    expect(pwd.validatePassword("ｐａｓｓｗｏｒｄ").valid).toBe(true);
  });
});

describe("Password() - verifyAndRehash", () => {
  test("returns valid:false for a wrong password, with no newHash", async () => {
    const pwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await pwd.hashPassword("correct-password");

    const result = await pwd.verifyAndRehash(hash, "wrong-password");
    expect(result).toEqual({ valid: false });
  });

  test("returns valid:true with no newHash when the hash is already current", async () => {
    const pwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await pwd.hashPassword("correct-password");

    const result = await pwd.verifyAndRehash(hash, "correct-password");
    expect(result.valid).toBe(true);
    expect(result.newHash).toBeUndefined();
  });

  test("returns a newHash when the password is valid but the hash uses outdated params", async () => {
    const oldPwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await oldPwd.hashPassword("correct-password");

    const newPwd = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 6 } });
    const result = await newPwd.verifyAndRehash(hash, "correct-password");

    expect(result.valid).toBe(true);
    expect(typeof result.newHash).toBe("string");
    expect(await newPwd.verifyPassword(result.newHash!, "correct-password")).toBe(true);
  });

  test("verifyAndRehash preserves the pepper marker on the rehashed output", async () => {
    const oldPwd = Password({ pepper: "p-secret", algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
    const hash = await oldPwd.pepperedHashPassword("correct-password");

    const newPwd = Password({ pepper: "p-secret", algorithm: "bcrypt", bcrypt: { saltRounds: 6 } });
    const result = await newPwd.verifyAndRehash(hash, "correct-password");

    expect(result.valid).toBe(true);
    expect(result.newHash).toMatch(/^\$pepper\$[0-9a-f]{8}\$/);
    expect(await newPwd.verifyPassword(result.newHash!, "correct-password")).toBe(true);
  });
});