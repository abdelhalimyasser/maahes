import { describe, expect, test } from "bun:test";
import { validatePassword, PasswordPolicyError, estimateEntropy } from "../../src/password/policy";
import type { PasswordPolicyOptions } from "../../src/password/types";

const BASE_POLICY: Required<PasswordPolicyOptions> = {
  minLength: 8,
  maxLength: 128,
  minUppercase: 0,
  minLowercase: 0,
  minDigits: 0,
  minSymbols: 0,
  minEntropy: 0,
  allowedScripts: ["Latin"],
  blockWhitespace: true,
  blockedPasswords: [],
  customRules: [],
  enforceOnHash: false,
};

describe("validatePassword", () => {
  test("accepts a password that satisfies the base policy", () => {
    const result = validatePassword("aValidPassword1", BASE_POLICY);
    expect(result.valid).toBe(true);
    expect(result.violations).toEqual([]);
  });

  test("rejects a password shorter than minLength", () => {
    const result = validatePassword("short", BASE_POLICY);
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("minLength");
  });

  test("rejects a password longer than maxLength", () => {
    const result = validatePassword("a".repeat(200), { ...BASE_POLICY, maxLength: 20 });
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("maxLength");
  });

  test("rejects whitespace when blockWhitespace is true", () => {
    const result = validatePassword("has a space1", BASE_POLICY);
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("whitespace");
  });

  test("allows whitespace when blockWhitespace is false", () => {
    const result = validatePassword("has a space1", { ...BASE_POLICY, blockWhitespace: false });
    expect(result.violations.map((v) => v.rule)).not.toContain("whitespace");
  });

  test("enforces minUppercase/minLowercase/minDigits/minSymbols independently", () => {
    const strict: Required<PasswordPolicyOptions> = {
      ...BASE_POLICY,
      minUppercase: 1,
      minLowercase: 1,
      minDigits: 1,
      minSymbols: 1,
    };

    const result = validatePassword("alllowercase", strict); // fails all four
    const rules = result.violations.map((v) => v.rule);

    expect(rules).toContain("minUppercase");
    expect(rules).toContain("minDigits");
    expect(rules).toContain("minSymbols");
    expect(rules).not.toContain("minLowercase"); // it IS all lowercase

    const passing = validatePassword("Valid1Pass!", strict);
    expect(passing.valid).toBe(true);
  });

  test("rejects characters from a script not in allowedScripts", () => {
    const result = validatePassword("password123", { ...BASE_POLICY, allowedScripts: ["Arabic"] });
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("allowedScripts");
  });

  test("accepts characters from any script listed in allowedScripts", () => {
    const result = validatePassword("baba1234", { ...BASE_POLICY, allowedScripts: ["Latin", "Arabic"] });
    expect(result.violations.map((v) => v.rule)).not.toContain("allowedScripts");
  });

  test("'Any' in allowedScripts disables the script check entirely", () => {
    const result = validatePassword("مرحبا12345", { ...BASE_POLICY, allowedScripts: ["Any"] });
    expect(result.violations.map((v) => v.rule)).not.toContain("allowedScripts");
  });

  test("rejects an exact blocklist match, case-insensitively", () => {
    const result = validatePassword("Password123", {
      ...BASE_POLICY,
      blockedPasswords: ["password123"],
    });
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("blockedPasswords");
  });
});

describe("validatePassword - minEntropy", () => {
  test("rejects a password below the entropy floor", () => {
    const policy = { ...BASE_POLICY, minEntropy: 80 };
    const result = validatePassword("aaaaaaaaaaaaaaaa", policy); // ~75 bits
    expect(result.valid).toBe(false);
    expect(result.violations.map((v) => v.rule)).toContain("minEntropy");
  });

  test("accepts a password above the entropy floor", () => {
    const policy = { ...BASE_POLICY, minEntropy: 80 };
    const result = validatePassword("Tr0ub4dor&3-G00d", policy); // ~90 bits
    expect(result.valid).toBe(true);
  });

  test("minEntropy: 0 disables the rule", () => {
    expect(validatePassword("aaaaaaaa", BASE_POLICY).valid).toBe(true);
  });
});

describe("validatePassword - customRules", () => {
  test("reports a violation when a custom rule fails, with a default message", () => {
    const policy: Required<PasswordPolicyOptions> = {
      ...BASE_POLICY,
      customRules: [{ rule: "noSequential", test: (pwd) => !/(.)\1{2,}/.test(pwd) }],
    };
    const result = validatePassword("abccc123", policy);

    expect(result.valid).toBe(false);
    expect(result.violations).toContainEqual({
      rule: "noSequential",
      message: 'Password failed custom rule "noSequential".',
    });
  });

  test("uses the custom message when provided", () => {
    const policy: Required<PasswordPolicyOptions> = {
      ...BASE_POLICY,
      customRules: [
        {
          rule: "noSequential",
          message: "Password must not contain 3+ identical characters in a row.",
          test: (pwd) => !/(.)\1{2,}/.test(pwd),
        },
      ],
    };
    const result = validatePassword("abccc123", policy);

    expect(result.violations).toContainEqual({
      rule: "noSequential",
      message: "Password must not contain 3+ identical characters in a row.",
    });
  });

  test("passing custom rules produce no violations", () => {
    const policy: Required<PasswordPolicyOptions> = {
      ...BASE_POLICY,
      customRules: [{ rule: "noSequential", test: (pwd) => !/(.)\1{2,}/.test(pwd) }],
    };
    expect(validatePassword("abc12345", policy).valid).toBe(true);
  });

  test("custom rules receive the resolved policy as the second argument", () => {
    let receivedPolicy: unknown;
    const policy: Required<PasswordPolicyOptions> = {
      ...BASE_POLICY,
      minLength: 4,
      customRules: [
        {
          rule: "inspectPolicy",
          test: (_pwd, p) => {
            receivedPolicy = p;
            return true;
          },
        },
      ],
    };
    validatePassword("abcd", policy);
    expect(receivedPolicy).toEqual(policy);
  });
});

describe("estimateEntropy", () => {
  test("returns 0 for an empty password", () => {
    expect(estimateEntropy("")).toBe(0);
  });

  test("is monotonic with length for a single class", () => {
    expect(estimateEntropy("aaa")).toBeLessThan(estimateEntropy("aaaaaaaa"));
  });

  test("mixed classes score higher than a single class of the same length", () => {
    expect(estimateEntropy("aaaaaa")).toBeLessThan(estimateEntropy("aA1!aA"));
  });

  test("counts code points, not UTF-16 units", () => {
    // "🅰" is a single code point (2 UTF-16 units): 1 char * log2(pool)
    const emojiBits = estimateEntropy("🅰");
    const singleAscii = estimateEntropy("a");
    expect(emojiBits).toBe(singleAscii);
  });
});

describe("PasswordPolicyError", () => {
  test("carries the violations it was constructed with", () => {
    const violations = [{ rule: "minLength", message: "too short" }];
    const error = new PasswordPolicyError(violations);

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("PasswordPolicyError");
    expect(error.violations).toEqual(violations);
  });
});