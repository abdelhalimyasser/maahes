#!/usr/bin/env node
/**
 * CORS on a real HTTP server: the middleware as a raw node:http handler
 * and as a Connect/Express-style chain step, with a browser-style
 * client (fetch with an Origin header) exercising preflight, simple
 * requests, denied origins and a cookie-carrying credentialed call.
 *
 * Run:  node examples/cors-server.mjs   (or: bun examples/cors-server.mjs)
 */

import { createServer } from "node:http";
import { Cors } from "../dist/index.js";

// ---- Configuration ----------------------------------------------------------
const cors = Cors({
  origin: [
    "https://app.example.com",
    "https://*.example.com", // glob
    { pattern: "https://admin.example.com", credentials: true },
  ],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  exposedHeaders: ["x-total-count"],
  maxAge: 3600,
  onBlock: ({ origin }) => console.log(`   [onBlock] denied ${origin}`),
});

// ---- Server 1: raw node:http handler (no framework) -------------------------
// middleware() with no `next` argument behaves as a complete request
// handler for preflights and decorates everything else.
const rawServer = createServer((req, res) => {
  cors.middleware()(req, res);
  if (res.writableEnded) return; // preflight answered by the CORS layer
  const body = JSON.stringify({ ok: true, echo: req.method });
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.end(body);
});

// ---- Server 2: Connect/Express-style chain ---------------------------------
// A framework is emulated with a tiny 3-step chain; the CORS middleware
// runs first and calls next() for simple requests, exactly like Express.
const chainServer = createServer((req, res) => {
  const steps = [
    cors.middleware(), // (req, res, next)
    (req, res, next) => {
      res.setHeader("X-Step", "auth-stub");
      next();
    },
    (req, res) => {
      const body = JSON.stringify({ ok: true, via: "chain" });
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Length", Buffer.byteLength(body));
      res.end(body);
    },
  ];
  let index = 0;
  const next = () => {
    const step = steps[index++];
    step(req, res, next);
  };
  next();
});

const listen = (server) =>
  new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });

const port1 = await listen(rawServer);
const port2 = await listen(chainServer);
console.log(`servers listening on :${port1} (raw) and :${port2} (chain)`);

const url = (port, path = "/data") => `http://127.0.0.1:${port}${path}`;
const check = (name, ok, detail) =>
  console.log(`${ok ? "✅" : "❌"} ${name}${detail ? `  — ${detail}` : ""}`);
if (![port1, port2].every((p) => p > 0)) process.exit(1);

// ---- Client: browser-style calls -------------------------------------------

// 1. Preflight: OPTIONS with Access-Control-Request-Method
const preflight = await fetch(url(port1), {
  method: "OPTIONS",
  headers: { origin: "https://sub.example.com", "access-control-request-method": "PATCH" },
});
check(
  "preflight answered 204",
  preflight.status === 204 && preflight.headers.get("Access-Control-Allow-Origin") === "https://sub.example.com"
);
check(
  "   Access-Control-Allow-Methods present",
  preflight.headers.get("Access-Control-Allow-Methods")?.includes("PATCH")
);
check("   Vary triptych present", preflight.headers.get("Vary")?.split(", ").length === 3);

// 2. Simple cross-origin GET → decorates the response
const simple = await fetch(url(port1), { headers: { origin: "https://app.example.com" } });
check(
  "simple GET decorated",
  simple.status === 200 && simple.headers.get("Access-Control-Allow-Origin") === "https://app.example.com"
);
check(
  "   exposes x-total-count",
  simple.headers.get("Access-Control-Expose-Headers") === "x-total-count"
);
check("   app body served", (await simple.json()).ok === true);

// 3. Denied origin → no CORS headers, body still served (browser enforces)
const denied = await fetch(url(port1), { headers: { origin: "https://evil.io" } });
check(
  "denied origin got no ACAO",
  denied.headers.get("Access-Control-Allow-Origin") === null
);
check(
  "   and no ACAC",
  denied.headers.get("Access-Control-Allow-Credentials") === null
);

// 4. Wildcard glob origin + credentialed admin rule → reflected origin
const credentialed = await fetch(url(port2), {
  method: "OPTIONS",
  headers: {
    origin: "https://admin.example.com",
    "access-control-request-method": "POST",
    "access-control-request-headers": "content-type",
  },
});
check(
  "admin rule granted credentials",
  credentialed.headers.get("Access-Control-Allow-Credentials") === "true" &&
    credentialed.headers.get("Access-Control-Allow-Origin") === "https://admin.example.com"
);

// 5. Chain server: last step runs for simple requests
const chained = await fetch(url(port2), { headers: { origin: "https://sub.example.com" } });
check(
  "chain step executed",
  chained.headers.get("X-Step") === "auth-stub" && (await chained.json()).via === "chain"
);

rawServer.close();
chainServer.close();

console.log("\ndone - CORS works on raw node:http and Connect-style chains");