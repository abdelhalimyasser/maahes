#!/usr/bin/env node
/**
 * Registration + login flow, end to end.
 *
 * A fake in-memory user store demonstrates the exact shapes you will
 * handle in a real application: policy errors at signup, uniform 401s at
 * login, and silent hash upgrades via verifyAndRehash when parameters
 * change. Run with:  node examples/registration-login.mjs   (or bun)
 */

import Password, { PasswordPolicyError } from "../dist/index.js";

// ---- App setup: one module per configuration, created at boot ------------
const pwd = Password({
  algorithm: "argon2",
  policy: {
    minLength: 10,
    minDigits: 1,
    minSymbols: 1,
    enforceOnHash: true, // reject weak passwords at the boundary
  },
});

// ---- Fake store -----------------------------------------------------------
const users = new Map(); // id -> { email, passwordHash }

async function saveUser(email, passwordHash) {
  const id = String(users.size + 1);
  users.set(id, { email, passwordHash });
  return id;
}

// ---- Registration handler -------------------------------------------------
async function register(email, plainPassword) {
  try {
    const hash = await pwd.hashPassword(plainPassword); // <- throws on policy violations
    const id = await saveUser(email, hash);
    return { status: 201, body: { id } };
  } catch (err) {
    if (err instanceof PasswordPolicyError) {
      return { status: 400, body: { error: "password_policy", violations: err.violations } };
    }
    throw err;
  }
}

// ---- Login handler ---------------------------------------------------------
async function login(email, plainPassword) {
  const user = [...users.values()].find((u) => u.email === email);
  if (!user) return { status: 401, body: { error: "invalid_credentials" } };

  const result = await pwd.verifyAndRehash(user.passwordHash, plainPassword);
  if (!result.valid) return { status: 401, body: { error: "invalid_credentials" } };

  // Silent upgrade: parameters changed since the hash was written.
  if (result.newHash && result.newHash !== user.passwordHash) {
    user.passwordHash = result.newHash;
    console.log(`  [store] upgraded hash for ${email}`);
  }

  return { status: 200, body: { message: "logged in" } };
}

// ---- Run -------------------------------------------------------------------
const pretty = (r) => `${r.status} ${JSON.stringify(r.body)}`;

console.log("== registration ==");
console.log(pretty(await register("alice@example.com", "weak"))); // 400 policy violation
console.log(pretty(await register("alice@example.com", "Tr0ub4dor&3-G00d"))); // 201

console.log("== login ==");
console.log(pretty(await login("alice@example.com", "wrong-password"))); // 401
console.log(pretty(await login("alice@example.com", "Tr0ub4dor&3-G00d"))); // 200

console.log("== parameter change triggers silent upgrade at next login ==");
// Simulate "next year": rounds config bumped. Old hashes keep working.
const newer = Password({ algorithm: "argon2", argon2: { timeCost: 4 } });
const alice = [...users.values()][0];
console.log("  old hash needs rehash:", await newer.needsRehash(alice.passwordHash));
const result = await newer.verifyAndRehash(alice.passwordHash, "Tr0ub4dor&3-G00d");
console.log("  login ok with new params:", result.valid, "| upgraded:", typeof result.newHash === "string");

console.log("\ndone - registration/login flow works");