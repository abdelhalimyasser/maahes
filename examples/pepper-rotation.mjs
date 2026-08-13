#!/usr/bin/env node
/**
 * Peppering, marker auto-detection and pepper rotation with the keyring.
 *
 * The modern keyring (`current` + optional `previous` secrets) gives
 * single-module rotation: the new secret is used for every new hash,
 * the old secret keeps verifying old hashes, and `verifyAndRehash`
 * transparently re-peppers old hashes onto the current secret.
 * Run:  node examples/pepper-rotation.mjs
 */

import Password, { isPepperedHash, detectHashAlgorithm } from "../dist/index.js";

// ---- Era 1: hashes written with the old secret ------------------------------
// The id must match the ring's `previous` entry so the marker routes to it.
const era1 = Password({ pepper: { current: { id: "2025-b", secret: "old-pepper-era" } } });
const oldEraHash = await era1.pepperedHashPassword("my-password-3");
console.log("era-1 hash (old secret):", oldEraHash);

// ---- Rotation: keyring with the new secret current, old in previous ---------
const pwd = Password({
  pepper: {
    current: { id: "2026-a", secret: "new-pepper-era" },
    previous: [{ id: "2025-b", secret: "old-pepper-era" }],
  },
});

// ---- Hashing and the marker -------------------------------------------------
const liveHash = await pwd.pepperedHashPassword("my-password-1");
console.log("\npeppered hash  :", liveHash);
console.log("  is marked    :", isPepperedHash(liveHash));
console.log("  inner algo   :", detectHashAlgorithm(liveHash)); // marker is transparent

// Marker-aware verification: the right secret is picked from the ring.
console.log("\nverifyPassword with current secret:", await pwd.verifyPassword(liveHash, "my-password-1"));

// ---- Legacy: unmarked hash, pepper applied manually (pre-marker era) --------
// Unmarked hashes carry no pepper identity - they verify only against a
// module configured with the exact secret that produced them.
import { createHmac } from "node:crypto";
const hmacOld = (pw) => createHmac("sha256", "old-pepper-era").update(pw).digest("hex");
const bareHash = await pwd.rehashPassword(hmacOld("my-password-2"));

console.log("\nlegacy bare hash is NOT marked:", isPepperedHash(bareHash));
console.log(
  "  ring verify (current, then previous secret):",
  await pwd.pepperedVerifyPassword(bareHash, "my-password-2")
);

// ---- Rotation: hashes from the previous era still verify --------------------
console.log("\nold-era hash verifies via the ring:", await pwd.verifyPassword(oldEraHash, "my-password-3"));
console.log("  needsRehash (pepper era changed) :", await pwd.needsRehash(oldEraHash));

// ---- verifyAndRehash: one call rotates the stored hash forward --------------
const outcome = await pwd.verifyAndRehash(oldEraHash, "my-password-3");
console.log("\nverifyAndRehash on old-era hash:");
console.log("  valid      :", outcome.valid);
console.log("  new hash   :", outcome.newHash);
console.log("  re-peppered:", outcome.newHash !== oldEraHash);
console.log("  current era:", outcome.newHash.startsWith("$pepper$2026-a$"));
console.log("  still verifies:", await pwd.verifyPassword(outcome.newHash, "my-password-3"));