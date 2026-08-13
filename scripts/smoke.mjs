#!/usr/bin/env node
/**
 * @fileoverview End-to-end smoke test for the built @maahes/core package.
 *
 * Exercises the password module exactly as a consumer would: hashing and
 * verifying with every algorithm, policy enforcement with custom rules,
 * peppering with the marker, entropy estimation, hash-format detection and
 * the login-time rehash flow. Then exercises the CORS module: preflight
 * and simple-request headers, glob/per-origin credentials, deny policies,
 * Vary merging, the middleware and the fetch wrapper. Runs against
 * `dist/` under BOTH Node.js (`npm run smoke:node`) and Bun
 * (`npm run smoke:bun`) to prove runtime compatibility.
 *
 * Exits non-zero on the first failed assertion.
 */

import { Password, Cors, detectHashAlgorithm, estimateEntropy, PasswordPolicyError } from "../dist/index.js";

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

  // 6) CORS: preflight + simple request with glob rules and credentials.
  const cors = Cors({
    origin: [
      "https://app.example.com",
      "https://*.example.com",
      { pattern: "https://admin.example.com", credentials: true },
    ],
    credentials: false,
    exposedHeaders: ["x-total-count"],
  });

  const preflight = cors.process({
    method: "OPTIONS",
    headers: {
      origin: "https://sub.example.com",
      "access-control-request-method": "PATCH",
      "access-control-request-headers": "content-type, x-token",
    },
  });
  assert(preflight.allowed && preflight.preflight, "cors: preflight allowed");
  assert(preflight.statusCode === 204, "cors: preflight 204");
  assert(preflight.headers["Access-Control-Allow-Origin"] === "https://sub.example.com", "cors: glob origin reflected");
  assert(preflight.headers["Access-Control-Allow-Headers"] === "content-type, x-token", "cors: requested headers reflected");
  assert(preflight.headers["Access-Control-Max-Age"] === "86400", "cors: default max-age");
  assert(preflight.headers["Vary"].split(", ").length === 3, "cors: Vary triptych");

  const simple = cors.process({
    method: "GET",
    headers: { origin: "https://app.example.com", vary: "Accept-Encoding" },
  });
  assert(simple.allowed && !simple.preflight, "cors: simple request allowed");
  assert(simple.headers["Access-Control-Allow-Origin"] === "https://app.example.com", "cors: exact origin reflected");
  assert(simple.headers["Access-Control-Allow-Credentials"] === undefined, "cors: global credentials stay off");
  assert(simple.headers["Access-Control-Expose-Headers"] === "x-total-count", "cors: expose headers");
  assert(simple.headers["Vary"] === "Accept-Encoding, Origin", "cors: Vary merged, not clobbered");

  const admin = cors.process({
    method: "GET",
    headers: { origin: "https://admin.example.com" },
  });
  assert(admin.headers["Access-Control-Allow-Credentials"] === "true", "cors: per-origin credentials override");

  const denied = cors.process({ method: "GET", headers: { origin: "https://evil.io" } });
  assert(!denied.allowed && denied.blocked, "cors: unknown origin blocked");
  assert(Object.keys(denied.headers).length === 0, "cors: block omits headers by default");

  const hard = Cors({ origin: ["https://app.example.com"], failureStatus: 403 }).process({
    method: "GET",
    headers: { origin: "https://evil.io" },
  });
  assert(hard.statusCode === 403, "cors: failureStatus hard-block");

  const wildcardWithCreds = Cors({ credentials: true }).process({
    method: "GET",
    headers: { origin: "https://whoever.example.com" },
  });
  assert(
    wildcardWithCreds.headers["Access-Control-Allow-Origin"] !== "*" &&
      wildcardWithCreds.headers["Access-Control-Allow-Credentials"] === "true",
    "cors: credentials never pair with a wildcard"
  );

  // 7) CORS: middleware + fetch surfaces.
  const headers = {};
  const middleware = Cors({ origin: ["https://app.example.com"] }).middleware();
  let nextCalled = false;
  middleware(
    { method: "GET", headers: { origin: "https://app.example.com" } },
    { setHeader: (n, v) => (headers[n] = v), statusCode: 200, end: () => {} },
    () => {
      nextCalled = true;
    }
  );
  assert(nextCalled, "cors: middleware calls next for simple requests");
  assert(headers["Access-Control-Allow-Origin"] === "https://app.example.com", "cors: middleware applied headers");

  const handle = Cors({ origin: ["https://app.example.com"], credentials: true }).fetchHandler((request) => {
    assert(request.headers.get("origin") === "https://app.example.com", "cors: fetch handler receives the request");
    return new Response("ok", { status: 200 });
  });
  const response = await handle(
    new Request("https://api.example.com/data", {
      method: "GET",
      headers: { origin: "https://app.example.com" },
    })
  );
  assert(response !== undefined && (await response.text()) === "ok", "cors: fetch wrapper returned handler body");
  assert(response.headers.get("Access-Control-Allow-Origin") === "https://app.example.com", "cors: fetch wrapper decorated response");

  console.log(`\nSMOKE OK: ${checks} checks passed (${process.execPath})`);
  process.exit(0);
}

run().catch((err) => {
  console.error("SMOKE FAIL:", err);
  process.exit(1);
});