// test/password/drivers/bcrypt.test.ts
import { describe, expect, test } from "bun:test";
import { createBcryptDriver } from "../../../src/password/drivers/bcrypt";

describe("bcrypt driver", () => {
  test("hash() produces a string that verify() accepts", async () => {
    const driver = createBcryptDriver({ saltRounds: 4 }); // low rounds -> fast tests
    const hash = await driver.hash("correct-horse-battery-staple");

    expect(typeof hash).toBe("string");
    expect(await driver.verify(hash, "correct-horse-battery-staple")).toBe(true);
  });

  test("verify() rejects a wrong password", async () => {
    const driver = createBcryptDriver({ saltRounds: 4 });
    const hash = await driver.hash("real-password");

    expect(await driver.verify(hash, "wrong-password")).toBe(false);
  });

  test("verify() returns false (never throws) on a malformed hash", async () => {
    const driver = createBcryptDriver({ saltRounds: 4 });
    await expect(driver.verify("not-a-real-hash", "anything")).resolves.toBe(false);
  });

  test("needsRehash() is false when rounds match the current config", async () => {
    const driver = createBcryptDriver({ saltRounds: 4 });
    const hash = await driver.hash("password123");

    expect(await driver.needsRehash(hash)).toBe(false);
  });

  test("needsRehash() is true when saltRounds config changes", async () => {
    const oldDriver = createBcryptDriver({ saltRounds: 4 });
    const hash = await oldDriver.hash("password123");

    const newDriver = createBcryptDriver({ saltRounds: 10 });
    expect(await newDriver.needsRehash(hash)).toBe(true);
  });

  test("passwords longer than 72 bytes still hash without throwing", async () => {
    const driver = createBcryptDriver({ saltRounds: 4 });
    const longPassword = "a".repeat(100);

    // bcrypt truncates at 72 bytes - this documents that behavior rather than hiding it.
    const hash = await driver.hash(longPassword);
    expect(await driver.verify(hash, longPassword)).toBe(true);
    // a password sharing the same first 72 bytes is treated as equal - known bcrypt limitation
    expect(await driver.verify(hash, "a".repeat(72) + "different-tail")).toBe(true);
  });

  test("preHash removes the 72-byte truncation limitation", async () => {
    const driver = createBcryptDriver({ saltRounds: 4, preHash: true });
    const longPassword = "a".repeat(100);

    const hash = await driver.hash(longPassword);
    expect(await driver.verify(hash, longPassword)).toBe(true);
    // with preHash the tail matters: the full 100-byte password is distinct
    expect(await driver.verify(hash, "a".repeat(72) + "different-tail")).toBe(false);
  });

  test("invalid options throw PasswordOptionsError at construction", () => {
    expect(() => createBcryptDriver({ saltRounds: 99 })).toThrow(/bcrypt/);
    expect(() => createBcryptDriver({ saltRounds: 3 })).toThrow(/bcrypt/);
    expect(() => createBcryptDriver({ saltRounds: 12.5 })).toThrow(/bcrypt/);
  });
});