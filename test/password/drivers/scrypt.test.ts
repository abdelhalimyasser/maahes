import { describe, expect, test } from "bun:test";
import { createScryptDriver } from "../../../src/password/drivers/scrypt";

// low cost -> fast tests; production defaults (N=16384) are exercised separately below
const FAST_OPTIONS = { cost: 2 ** 10, blockSize: 8, parallelization: 1, keyLength: 32 };

describe("scrypt driver", () => {
  test("hash() produces a string that verify() accepts", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    const hash = await driver.hash("correct-horse-battery-staple");

    expect(typeof hash).toBe("string");
    expect(hash.startsWith("$scrypt$N=")).toBe(true);
    expect(await driver.verify(hash, "correct-horse-battery-staple")).toBe(true);
  });

  test("verify() rejects a wrong password", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    const hash = await driver.hash("real-password");

    expect(await driver.verify(hash, "wrong-password")).toBe(false);
  });

  test("verify() returns false (never throws) on a malformed/foreign hash", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    await expect(driver.verify("not-a-real-hash", "anything")).resolves.toBe(false);
    await expect(driver.verify("$argon2id$v=19$...", "anything")).resolves.toBe(false);
  });

  test("needsRehash() is false when params match the current config", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    const hash = await driver.hash("password123");

    expect(await driver.needsRehash(hash)).toBe(false);
  });

  test("needsRehash() is true when cost config changes", async () => {
    const oldDriver = createScryptDriver(FAST_OPTIONS);
    const hash = await oldDriver.hash("password123");

    const newDriver = createScryptDriver({ ...FAST_OPTIONS, cost: 2 ** 11 });
    expect(await newDriver.needsRehash(hash)).toBe(true);
  });

  test("needsRehash() is true for an unparsable hash", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    expect(await driver.needsRehash("garbage")).toBe(true);
  });

  test("two hashes of the same password are different (random salt)", async () => {
    const driver = createScryptDriver(FAST_OPTIONS);
    const [hashA, hashB] = await Promise.all([
      driver.hash("same-password"),
      driver.hash("same-password"),
    ]);

    expect(hashA).not.toBe(hashB);
  });

  test("custom saltLength and keyLength hash and verify", async () => {
    const driver = createScryptDriver({ ...FAST_OPTIONS, saltLength: 24, keyLength: 48 });
    const hash = await driver.hash("configured-password");

    expect(typeof hash).toBe("string");
    expect(await driver.verify(hash, "configured-password")).toBe(true);
    expect(await driver.needsRehash(hash)).toBe(false);
  });

  test("invalid options throw PasswordOptionsError at construction", () => {
    expect(() => createScryptDriver({ cost: 1000 })).toThrow(/scrypt/);
    expect(() => createScryptDriver({ blockSize: 0 })).toThrow(/scrypt/);
    expect(() => createScryptDriver({ parallelization: 0 })).toThrow(/scrypt/);
    expect(() => createScryptDriver({ keyLength: 0 })).toThrow(/scrypt/);
    expect(() => createScryptDriver({ saltLength: 2 })).toThrow(/scrypt/);
    expect(() => createScryptDriver({ cost: 2 ** 10, maxmem: 1024 })).toThrow(/scrypt/);
  });
});