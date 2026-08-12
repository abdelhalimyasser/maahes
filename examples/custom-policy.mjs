#!/usr/bin/env node
/**
 * A hardened password policy with custom rules.
 *
 * Demonstrates every built-in rule plus user-defined constraints
 * (no sequential repeats, no keyboard runs), NFKC normalization and the
 * two enforcement surfaces.  Run:  node examples/custom-policy.mjs
 */

import Password, { PasswordPolicyError, estimateEntropy } from "../dist/index.js";

// ---- A strict, production-style policy -------------------------------------
const pwd = Password({
  normalize: "nfkc", // full-width "ｐａｓｓ" folds to "pass"
  policy: {
    minLength: 10,
    maxLength: 64,
    minUppercase: 1,
    minLowercase: 1,
    minDigits: 1,
    minSymbols: 1,
    minEntropy: 50,
    allowedScripts: ["Latin"],
    blockWhitespace: true,
    blockedPasswords: ["Password123!", "qwerty12345"],
    customRules: [
      { rule: "noSequential", test: (p) => !/(.)\1{2,}/.test(p) },
      { rule: "noKeyboardRun", test: (p) => !/(qwerty|asdf|zxcv)/i.test(p) },
      {
        rule: "notAnOldPassword",
        message: "Must differ from the two previous passwords.",
        test: (p) => !["MyOldPass1!", "OlderPass2!"].includes(p),
      },
    ],
    enforceOnHash: true,
  },
});

// ---- Surface 1: validatePassword, non-throwing -----------------------------
const candidates = [
  "Tr0ub4dor&3-G00d", // strong
  "password",         // too short, no classes
  "Passssssss1!",     // sequential repeat
  "MyQwerty1!",       // keyboard run
  "MyOldPass1!",      // old password
  "Tr0ub4dor!",       // missing digit + entropy
  "ｐａｓｓｗｏｒｄ１２３４５６７", // full-width - folds to 16 chars, fails class checks
];

for (const candidate of candidates) {
  const { valid, violations } = pwd.validatePassword(candidate);
  console.log(
    `${valid ? "✅" : "❌"} ${JSON.stringify(candidate)}  entropy=${estimateEntropy(candidate)} bits` +
      (valid ? "" : `  → [${violations.map((v) => v.rule).join(", ")}]`)
  );
}

// ---- Surface 2: enforceOnHash at the signup boundary ------------------------
console.log("\n== enforceOnHash ==");
try {
  await pwd.hashPassword("Passssssss1!");
  console.log("unexpectedly accepted");
} catch (err) {
  if (err instanceof PasswordPolicyError) {
    console.log(`hashPassword rejected: ${err.message}`);
  }
}

const strong = await pwd.hashPassword("Tr0ub4dor&3-G00d");
console.log("strong password hashed:", strong.split("$")[1]);
console.log("   ...and verifies:", await pwd.verifyPassword(strong, "Tr0ub4dor&3-G00d"));

console.log("\ndone - custom policy works");