// test/password/drivers/argon2.test.ts
import { describe, expect, test } from "bun:test";
import { createArgon2Driver } from "../../../src/password/drivers/argon2";

describe("argon2 driver", () => {
  test("hash() produces a string that verify() accepts", async () => {
    const driver = createArgon2Driver();
    const hash = await driver.hash("correct-horse-battery-staple");

    expect(typeof hash).toBe("string");
    expect(await driver.verify(hash, "correct-horse-battery-staple")).toBe(true);
  });

  test("verify() rejects a wrong password", async () => {
    const driver = createArgon2Driver();
    const hash = await driver.hash("real-password");

    expect(await driver.verify(hash, "wrong-password")).toBe(false);
  });

  test("verify() returns false (never throws) on a malformed hash", async () => {
    const driver = createArgon2Driver();
    await expect(driver.verify("not-a-real-hash", "anything")).resolves.toBe(false);
  });

  test("needsRehash() is false right after hashing with the same config", async () => {
    const driver = createArgon2Driver({ timeCost: 2 });
    const hash = await driver.hash("password123");

    expect(await driver.needsRehash(hash)).toBe(false);
  });

  test("needsRehash() is true when a stricter config is used to check an old hash", async () => {
    const looseDriver = createArgon2Driver({ timeCost: 2 });
    const hash = await looseDriver.hash("password123");

    const strictDriver = createArgon2Driver({ timeCost: 5 });
    expect(await strictDriver.needsRehash(hash)).toBe(true);
  });

  test("two hashes of the same password are different (random salt)", async () => {
    const driver = createArgon2Driver();
    const [hashA, hashB] = await Promise.all([
      driver.hash("same-password"),
      driver.hash("same-password"),
    ]);

    expect(hashA).not.toBe(hashB);
  });

  test("custom hashLength/saltLength/version configs hash and verify", async () => {
    const driver = createArgon2Driver({ hashLength: 48, saltLength: 24, version: 0x13 });
    const hash = await driver.hash("configured-password");

    expect(typeof hash).toBe("string");
    expect(await driver.verify(hash, "configured-password")).toBe(true);
    expect(await driver.needsRehash(hash)).toBe(false);
  });

  test("invalid options throw PasswordOptionsError at construction", () => {
    expect(() => createArgon2Driver({ memoryCost: 4 })).toThrow(/argon2/);
    expect(() => createArgon2Driver({ timeCost: 0 })).toThrow(/argon2/);
    expect(() => createArgon2Driver({ parallelism: 0 })).toThrow(/argon2/);
  });
});