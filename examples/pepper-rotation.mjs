#!/usr/bin/env node
/**
 * Peppering, marker auto-detection and pepper rotation.
 *
 * Shows: marker shape, automatic pepper during verifyPassword, legacy
 * unmarked peppered hashes, and a dual-verify rotation window where
 * old-pepper hashes keep working while new hashes use the new secret.
 * Run:  node examples/pepper-rotation.mjs
 */

import Password, { isPepperedHash, detectHashAlgorithm } from "../dist/index.js";

// ---- Setup: one secret per "era" --------------------------------------------
const OLD_SECRET = "old-pepper-era";
const NEW_SECRET = "new-pepper-era";

const legacy = Password({ pepper: OLD_SECRET });
const current = Password({ pepper: NEW_SECRET });

// ---- Hashing and the marker -------------------------------------------------
const liveHash = await current.pepperedHashPassword("my-password-1");
console.log("peppered hash  :", liveHash);
console.log("  is marked    :", isPepperedHash(liveHash));
console.log("  inner algo   :", detectHashAlgorithm(liveHash)); // marker is transparent

// Marker-aware verification: no way to forget the pepper.
console.log("\nverifyPassword with current pepper:", await current.verifyPassword(liveHash, "my-password-1"));
console.log("verifyPassword with WRONG pepper :", await legacy.verifyPassword(liveHash, "my-password-1"));

// ---- Legacy: unmarked hash, pepper applied manually (pre-marker era) --------
// Simulate a hash written before markers existed: HMAC-peppered, stored bare.
import { createHmac } from "node:crypto";
const hmacOld = (pw) => createHmac("sha256", OLD_SECRET).update(pw).digest("hex");
const bareHash = await legacy.rehashPassword(hmacOld("my-password-2"));

console.log("\nlegacy bare hash is NOT marked:", isPepperedHash(bareHash));
console.log("  pepperedVerifyPassword (old-era module):", await legacy.pepperedVerifyPassword(bareHash, "my-password-2"));
// Unmarked hashes carry no pepper identity - they can ONLY be verified with
// a module configured with the secret that produced them. A module using a
// different pepper (e.g. v2 with NEW_SECRET) cannot verify it:
const v2 = Password({ pepper: NEW_SECRET });
console.log(
  "  v2 (new pepper) verify of old-pepper bare hash:",
  await v2.pepperedVerifyPassword(bareHash, "my-password-2"),
  "(correct - the pepper differs)"
);

// ---- Rotation: dual-verify window -------------------------------------------
const oldEraHash = await legacy.pepperedHashPassword("my-password-3");
const newEraHash = await current.pepperedHashPassword("my-password-3");

async function verifyDual(stored, password) {
  if (await current.verifyPassword(stored, password)) return "current";
  if (await legacy.verifyPassword(stored, password)) return "legacy-era";
  return null;
}

console.log("\n== rotation window ==");
console.log("old-era hash verifies via :", await verifyDual(oldEraHash, "my-password-3"));
console.log("new-era hash verifies via :", await verifyDual(newEraHash, "my-password-3"));

// Upgrade an old-era hash the moment its owner logs in.
if ((await verifyDual(oldEraHash, "my-password-3")) === "legacy-era") {
  const upgraded = await current.pepperedHashPassword("my-password-3");
  console.log("  upgraded to new pepper:", upgraded.startsWith("$pepper$"));
}

console.log("\ndone - peppering & rotation work");