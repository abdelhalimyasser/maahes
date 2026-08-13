/**
 * @fileoverview Web-standard fetch adapter for the security headers
 * engine.
 *
 * Runtime integration only — the engine itself stays pure. The wrapper:
 * - derives the secure context from the request URL (`https://`),
 * - delegates to the wrapped handler WITHOUT swallowing its errors,
 * - produces a new `Response` preserving status, statusText and body,
 * - applies `remove` and `overwrite` semantics against the handler's
 *   own response headers.
 *
 * Works on Node ≥ 18, Bun and edge runtimes.
 *
 * @module headers/fetch
 */

import type { HeaderBuildContext, SecurityHeadersNextCallback } from "./types";
import type { ResolvedSecurityHeadersConfig } from "./config";

/**
 * Creates the fetch wrapper for a resolved configuration.
 *
 * @param config - Fully-resolved configuration.
 * @param build - The pure engine function (`buildHeaderSet`).
 * @param handler - The underlying request handler.
 * @returns A wrapped handler decorating every response.
 */
export function createFetchHandler(
  config: ResolvedSecurityHeadersConfig,
  build: (context: HeaderBuildContext) => ReturnType<typeof import("./core").buildHeaderSet>,
  handler: (request: Request) => Response | Promise<Response>
): (request: Request) => Promise<Response> {
  return async (request) => {
    const secure = request.url.startsWith("https://");
    const response = await handler(request); // downstream errors propagate

    const plan = build({ secure, existing: response.headers });

    const merged = new Headers(response.headers);
    for (const name of plan.removed) merged.delete(name);
    for (const [name, value] of Object.entries(plan.headers)) {
      merged.set(name, value);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: merged,
    });
  };
}

export type { SecurityHeadersNextCallback };