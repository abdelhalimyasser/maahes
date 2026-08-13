#!/usr/bin/env node
/**
 * The Web-standard CORS wrapper on a real server: Request/Response in,
 * Request/Response out — the same adapter works on Bun.serve, Node's
 * undici-based stacks and edge runtimes, and it can wrap an existing
 * route handler.
 *
 * Run:  node examples/cors-fetch.mjs   (or: bun examples/cors-fetch.mjs)
 */

import { createServer } from "node:http";
import { Cors } from "../dist/index.js";

// ---- A CORS module whose origin resolution is dynamic -----------------------
// The callback form runs through the async path (processAsync) and is
// the natural fit for allow/deny decisions that need I/O (rate limits,
// allowlists in a database, ...).
const cors = Cors({
  origin: (origin, callback) => {
    const allowed = origin === "https://app.example.com" || origin === "https://admin.example.com";
    callback(null, allowed);
  },
  credentials: true,
});

// ---- The application route being wrapped ------------------------------------
const route = async (request) => {
  const body = JSON.stringify({ hello: "world", you: request.headers.get("user-agent") ?? "unknown" });
  return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
};

const handle = cors.fetchHandler(route);

// ---- Wire it into a plain HTTP server with a tiny Request bridge ------------
const server = createServer(async (req, res) => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, {
    method: req.method,
    headers,
  });

  const response = await handle(request);
  if (!response) {
    res.statusCode = 404;
    res.end("no route");
    return;
  }
  res.statusCode = response.status;
  for (const [name, value] of response.headers) res.setHeader(name, value);
  res.end(Buffer.from(await response.arrayBuffer()));
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
const url = (path) => `http://127.0.0.1:${port}${path}`;

// ---- 1. Preflight: answered by the CORS layer, route never runs -------------
const preflight = await fetch(url("/data"), {
  method: "OPTIONS",
  headers: { origin: "https://admin.example.com", "access-control-request-method": "DELETE" },
});
console.log(
  preflight.status === 204
    ? "✅ preflight answered by fetchHandler with 204"
    : `❌ preflight status ${preflight.status}`
);

// ---- 2. Simple request: wrapped handler response is decorated ---------------
const simple = await fetch(url("/data"), { headers: { origin: "https://app.example.com" } });
const body = await simple.json();
console.log(
  simple.headers.get("Access-Control-Allow-Origin") === "https://app.example.com" &&
    simple.headers.get("Access-Control-Allow-Credentials") === "true" &&
    body.hello === "world"
    ? "✅ handler response decorated with reflected origin + credentials"
    : "❌ handler response not decorated correctly"
);

// ---- 3. Callback denies an unknown origin -----------------------------------
const denied = await fetch(url("/data"), { headers: { origin: "https://evil.io" } });
const deniedHeaders = denied.headers.get("Access-Control-Allow-Origin");
console.log(
  denied.status === 403 && deniedHeaders === null ? "✅ unknown origin rejected with 403" : "❌ rejection broken"
);

// ---- 4. No Origin header: plain request passes through to the route ---------
const plain = await fetch(url("/data"));
console.log(
  (await plain.json()).hello === "world" ? "✅ same-origin request untouched" : "❌ same-origin request broken"
);

server.close();

console.log("\ndone - CORS works through the Web-standard fetch wrapper");