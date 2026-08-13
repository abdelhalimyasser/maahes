#!/usr/bin/env node
/**
 * Security headers on a plain Node HTTP server (no frameworks).
 *
 * Shows: preset-based defaults, HSTS only on TLS sockets, removal of
 * fingerprinting headers, and secure-context handling on HTTP.
 * Run:  node examples/headers-server.mjs   (then curl -i localhost:3000)
 */

import { createServer } from "node:http";
import { SecurityHeaders } from "../dist/index.js";

const headers = SecurityHeaders({
  preset: "default",
  remove: ["Server", "X-Powered-By"],
  extra: { "X-Request-Id": "maahes-demo" },
});

const server = createServer((req, res) => {
  headers.middleware()(req, res, () => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("hello from maahes\n");
  });
});

server.listen(3000, () => {
  console.log("listening on http://localhost:3000");
  console.log("expected headers:");
  const plan = headers.build({ secure: false }); // HTTP: no HSTS
  for (const [name, value] of Object.entries(plan.headers)) console.log(`  ${name}: ${value}`);
});