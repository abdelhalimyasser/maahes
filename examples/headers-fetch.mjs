#!/usr/bin/env node
/**
 * Security headers on a Web-standard fetch handler (Bun, Deno, edge).
 *
 * Shows: httpsOnly semantics (HSTS from https:// URLs), overwrite
 * semantics against the handler's own headers, and Set-Cookie survival.
 * Run:  node examples/headers-fetch.mjs   (then curl -i localhost:3001)
 */

import { createServer } from "node:http";
import { SecurityHeaders } from "../dist/index.js";

const headers = SecurityHeaders({
  preset: "strict",
  remove: ["X-Powered-By"],
});

const handle = headers.fetchHandler(async (request) => {
  const url = new URL(request.url);
  const body = `you asked for ${url.pathname}\n`;
  const response = new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/plain",
      // The engine overwrites this on an https:// request…
      "X-Frame-Options": "SAMEORIGIN",
      // …and this is removed.
      "X-Powered-By": "node",
    },
  });
  return response;
});

// The same handler logic runs on any Web-standard server (Bun's
// `Bun.serve({ fetch: handle })`, Deno, Cloudflare Workers, …). Here we
// bridge it into a plain Node HTTP server to keep the example dependency-free.
const server = createServer(async (req, res) => {
  const response = await handle(new Request(`http://localhost:3001${req.url ?? "/"}`, { method: req.method }));
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(await response.text());
});

server.listen(3001, () => {
  console.log("listening on http://localhost:3001");
  console.log("expected headers (http:// context: no HSTS):");
  for (const [name, value] of Object.entries(headers.build({ secure: false }).headers)) {
    console.log(`  ${name}: ${value}`);
  }
});