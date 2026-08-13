/**
 * @fileoverview The `Cors()` factory — assembles the compiled engine
 * and exposes the framework-agnostic surfaces (process/processAsync,
 * Connect middleware, raw node handler, fetch wrapper) from a single
 * immutable configuration.
 *
 * Mirrors the Password module's factory contract: signature `Cors()`
 * for defaults, `Cors(config)` for an object, JSON string or JSON file
 * path; configuration errors throw `CorsOptionsError` at construction
 * so misconfiguration fails at boot, never in request handlers.
 *
 * @module cors/factory
 */

import { createEngine, isPreflight, type CorsEngine } from "./core";
import { CorsOptionsError, parseCorsConfigInput, resolveConfig } from "./config";
import { compileOrigin, type CompiledOrigin } from "./matchers";
import type { CorsConfig, CorsModule, CorsRequestInput, CorsResult } from "./types";

/**
 * Creates a CORS module bound to a configuration.
 *
 * @param input - Configuration object, inline JSON string, or path to a
 *   JSON file (an optional `{"cors": ...}` wrapper is unpacked).
 *   Omit for secure defaults.
 * @returns The immutable, share-safe CORS module.
 * @throws {CorsOptionsError} When the configuration is invalid.
 */
export function Cors(input?: CorsConfig | string): CorsModule {
  const config = resolveConfig(parseCorsConfigInput(input));
  const matcher: CompiledOrigin = compileOrigin(config);
  const engine: CorsEngine = createEngine(config, matcher);
  const preflightMode = config.preflight ?? "auto";

  const process = (requestInput: CorsRequestInput): CorsResult => {
    if (matcher.kind === "callback") {
      throw new CorsOptionsError(
        "cors: callback-based origins require processAsync() — the sync process() cannot wait for I/O."
      );
    }
    return engine.process(requestInput);
  };

  return {
    process,
    processAsync: (requestInput) => engine.processAsync(requestInput),
    middleware: () => createMiddleware(engine),
    fetchHandler: (handler) => createFetchHandler(engine, handler),
    isPreflight: (requestInput) => isPreflight(requestInput, preflightMode ?? "auto"),
    allowedOrigin: (origin) => {
      if (origin === undefined) return null;
      const resolution = engine.resolveOrigin(origin);
      return resolution.allowed ? origin : null;
    },
  };
}

type Middleware = ReturnType<NonNullable<CorsModule["middleware"]>>;

/**
 * Connect/Express-style middleware. With `next` it behaves like the npm
 * `cors` package; without it, it acts as a raw `node:http` handler that
 * ends preflight and blocked responses.
 */
function createMiddleware(engine: CorsEngine): Middleware {
  return (req, res, next) => {
    const result = engine.process({ method: req.method, headers: req.headers });

    for (const [name, value] of Object.entries(result.headers)) {
      res.setHeader(name, value);
    }

    if (!result.allowed) {
      if (result.statusCode !== undefined) {
        res.statusCode = result.statusCode;
        res.end();
      } else {
        // Omit-header mode: the browser enforces the block; the request
        // itself may still be served (downloads, redirects, ...).
        next?.();
      }
      return;
    }
    if (result.preflight) {
      res.statusCode = result.statusCode ?? 204;
      res.end();
      return;
    }
    next?.();
  };
}

/** Web-standard CORS adapter for Bun, Node ≥ 18 and edge runtimes. */
function createFetchHandler(
  engine: CorsEngine,
  handler?: (request: Request) => Response | Promise<Response>
): (request: Request) => Promise<Response | undefined> {
  return async (request) => {
    const headers: Record<string, string> = {};
    request.headers.forEach((value, name) => {
      headers[name] = value;
    });

    const result = await engine.processAsync({
      method: request.method,
      headers,
    });

    if (!result.allowed) {
      return new Response(null, {
        status: result.statusCode ?? 403,
        headers: result.headers,
      });
    }
    if (result.preflight) {
      return new Response(null, {
        status: result.statusCode ?? 204,
        headers: result.headers,
      });
    }
    if (handler) {
      const response = await handler(request);
      const merged = new Headers(response.headers);
      for (const [name, value] of Object.entries(result.headers)) {
        merged.set(name, value);
      }
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: merged,
      });
    }
    return undefined;
  };
}