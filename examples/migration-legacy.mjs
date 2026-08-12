#!/usr/bin/env node
/**
 * Migrating an existing legacy store into Maahes.
 *
 * Simulates a system that stored plain bcrypt hashes (via the original
 * `bcrypt` package), then routes on detectHashAlgorithm, verifies with
 * the matching module and upgrades the hash on the user's next login.
 * Run:  node examples/migration-legacy.mjs
 */

import bcrypt from "bcrypt"; // the "old" system's library
import Password, { detectHashAlgorithm } from "../dist/index.js";

// ---- The legacy store: plain bcrypt hashes (e.g. from another framework) ----
const legacyBcryptRounds = 10;
const legacyStore = new Map([
  ["alice@example.com", await bcrypt.hash("Alice-Old-Pass-1", legacyBcryptRounds)],
  ["bob@example.com", await bcrypt.hash("Bob-Old-Pass-2", legacyBcryptRounds)],
]);

// ---- New system configuration: Argon2id, hardened ---------------------------
const currentPwd = Password({
  algorithm: "argon2", // target algorithm - whatever you choose
  policy: { minLength: 10, enforceOnHash: true },
});

// ---- Routing table: one reader per supported legacy format -------------------
const readers = {
  argon2: Password({ algorithm: "argon2" }),
  bcrypt: Password({ algorithm: "bcrypt" }),
  scrypt: Password({ algorithm: "scrypt" }),
};

async function login(email, plainPassword) {
  const stored = legacyStore.get(email);
  if (!stored) return { status: 401, body: { error: "invalid_credentials" } };

  // 1. What produced this hash?
  const algo = detectHashAlgorithm(stored);
  console.log(`  detected '${email}' hash as: ${algo}`);

  if (algo && readers[algo]) {
    // 2. Standard encoding → verify straight from the store.
    const ok = await readers[algo].verifyPassword(stored, plainPassword);
    if (!ok) return { status: 401, body: { error: "invalid_credentials" } };

    // 3. Upgrade on the spot to the target algorithm + modern parameters.
    const upgraded = await currentPwd.rehashPassword(plainPassword);
    legacyStore.set(email, upgraded);
    console.log(`  upgraded '${email}' to ${detectHashAlgorithm(upgraded)} (${upgraded.slice(0, 30)}…)`);
    return { status: 200, body: { message: "logged in, hash upgraded" } };
  }

  // 4. Unrecognized (e.g. SHA-1) - legacy code path, upgrade on success.
  //    (not simulated here - see docs/password.md#7-flows)
  return { status: 500, body: { error: "unsupported_hash" } };
}

// ---- Run ---------------------------------------------------------------------
console.log("== migration ==");
console.log(JSON.stringify(await login("alice@example.com", "wrong")));
console.log(JSON.stringify(await login("alice@example.com", "Alice-Old-Pass-1")));
console.log(JSON.stringify(await login("bob@example.com", "Bob-Old-Pass-2")));

console.log("\nstore now holds:", [...legacyStore.keys()].map((k) => `${k} → ${detectHashAlgorithm(legacyStore.get(k))}`).join(", "));

// Bob logs in again later - the hash is already modern, no re-upgrade.
console.log("\nsecond login for bob (already upgraded):");
const result = await currentPwd.verifyAndRehash(legacyStore.get("bob@example.com"), "Bob-Old-Pass-2");
console.log("  valid:", result.valid, "| needs another rehash:", typeof result.newHash === "string");

console.log("\ndone - migration works");