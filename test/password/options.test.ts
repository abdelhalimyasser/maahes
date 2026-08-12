import { describe, expect, test } from "bun:test";
import { Password, PasswordOptionsError } from "../../src/password/index";

describe("Password() - construction-time option validation", () => {
  test("rejects invalid argon2 memoryCost (below 8 * parallelism)", () => {
    expect(() => Password({ argon2: { memoryCost: 4, parallelism: 1 } })).toThrow(PasswordOptionsError);
  });

  test("rejects invalid argon2 timeCost and parallelism", () => {
    expect(() => Password({ argon2: { timeCost: 0 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { parallelism: 0 } })).toThrow(PasswordOptionsError);
  });

  test("rejects invalid argon2 hashLength, saltLength and version", () => {
    expect(() => Password({ argon2: { hashLength: 2 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { saltLength: 4 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ argon2: { version: 0x12 as any } })).toThrow(PasswordOptionsError);
  });

  test("rejects bcrypt saltRounds outside 4..31", () => {
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 3 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 32 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 12.5 } })).toThrow(PasswordOptionsError);
  });

  test("rejects non-power-of-two scrypt cost", () => {
    expect(() => Password({ algorithm: "scrypt", scrypt: { cost: 1000 } })).toThrow(PasswordOptionsError);
  });

  test("rejects zero/negative scrypt blockSize, parallelization, keyLength, saltLength", () => {
    expect(() => Password({ algorithm: "scrypt", scrypt: { blockSize: 0 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { parallelization: 0 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { keyLength: 0 } })).toThrow(PasswordOptionsError);
    expect(() => Password({ algorithm: "scrypt", scrypt: { saltLength: 2 } })).toThrow(PasswordOptionsError);
  });

  test("rejects scrypt maxmem below the memory requirement", () => {
    expect(() => Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 10, blockSize: 8, maxmem: 1024 } })).toThrow(
      PasswordOptionsError
    );
  });

  test("valid option sets construct without throwing", () => {
    expect(() => Password({ argon2: { memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 } })).not.toThrow();
    expect(() => Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 12 } })).not.toThrow();
    expect(() => Password({ algorithm: "scrypt", scrypt: { cost: 2 ** 14, blockSize: 8, parallelization: 1 } })).not.toThrow();
  });
});