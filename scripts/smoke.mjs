#!/usr/bin/env node
/**
 * @fileoverview End-to-end smoke test for the built @maahes/core package.
 *
 * Exercises the password module exactly as a consumer would: hashing and
 * verifying with every algorithm, policy enforcement with custom rules,
 * peppering with the marker, entropy estimation, hash-format detection and
 * the login-time rehash flow. Runs against `dist/` under BOTH Node.js
 * (`npm run smoke:node`) and Bun (`npm run smoke:bun`) to prove runtime
 * compatibility of the native dependencies (argon2, bcrypt).
 *
 * Exits non-zero on the first failed assertion.
 */

import { Password, detectHashAlgorithm, estimateEntropy, PasswordPolicyError } from "../dist/index.js";

let checks = 0;

function assert(condition, label) {
  checks += 1;
  if (!condition) {
    console.error(`SMOKE FAIL: ${label}`);
    process.exit(1);
  }
}

async function run() {
  // 1) Every algorithm round-trips and is detected correctly.
  for (const algorithm of ["argon2", "bcrypt", "scrypt"]) {
    const pwd = Password({
      algorithm,
      bcrypt: { saltRounds: 4 }, // fast for smoke
      scrypt: { cost: 2 ** 10 }, // fast for smoke
    });
    const hash = await pwd.hashPassword("correct-horse-battery-staple");
    assert(typeof hash === "string" && hash.length > 20, `${algorithm}: hash produced`);
    assert(await pwd.verifyPassword(hash, "correct-horse-battery-staple"), `${algorithm}: verify ok`);
    assert((await pwd.verifyPassword(hash, "wrong-password")) === false, `${algorithm}: wrong password rejected`);
    assert(detectHashAlgorithm(hash) === algorithm, `${algorithm}: detected as ${algorithm}`);
    assert((await pwd.needsRehash(hash)) === false, `${algorithm}: no rehash needed`);
    console.log(`  ok  ${algorithm}`);
  }

  // 2) Policy + custom rules + enforceOnHash.
  const pwd = Password({
    policy: {
      minLength: 10,
      minDigits: 1,
      minSymbols: 1,
      minEntropy: 40,
      allowedScripts: ["Latin"],
      enforceOnHash: true,
      customRules: [{ rule: "noSequential", test: (p) => !/(.)\1{2,}/.test(p) }],
    },
  });
  assert(!pwd.validatePassword("short").valid, "policy: short password rejected");
  assert(pwd.validatePassword("Tr0ub4dor&3-G00d").valid, "policy: strong password accepted");
  try {
    await pwd.hashPassword("passssss1!");
    assert(false, "policy: enforceOnHash throws");
  } catch (err) {
    assert(err instanceof PasswordPolicyError, "policy: throws PasswordPolicyError");
  }

  // 3) Peppering with the auto-detect marker.
  const peppered = Password({ pepper: process.env.PASSWORD_PEPPER ?? "smoke-pepper" });
  const phash = await peppered.pepperedHashPassword("pepper-me-123");
  assert(phash.startsWith("$pepper$"), "pepper: marker present");
  assert(await peppered.verifyPassword(phash, "pepper-me-123"), "pepper: auto-verify on marker");

  // 4) Entropy utility.
  assert(estimateEntropy("aaaaaaaa") < estimateEntropy("aA1!aA1!"), "entropy: mixed classes score higher");

  // 5) Login-time rehash flow.
  const oldCfg = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 4 } });
  const stored = await oldCfg.hashPassword("login-pass-123");
  const upgraded = Password({ algorithm: "bcrypt", bcrypt: { saltRounds: 6 } });
  const outcome = await upgraded.verifyAndRehash(stored, "login-pass-123");
  assert(outcome.valid === true && typeof outcome.newHash === "string", "verifyAndRehash: rehashed on param bump");

  console.log(`\nSMOKE OK: ${checks} checks passed (${process.execPath})`);
  process.exit(0);
}

run().catch((err) => {
  console.error("SMOKE FAIL:", err);
  process.exit(1);
});