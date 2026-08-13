/**
 * @fileoverview Connect/Express-style middleware adapter for the
 * security headers engine.
 *
 * Runtime integration only — it never touches the core engine's purity.
 * Behavior contract:
 * - decorates the response and ALWAYS calls `next()`,
 * - never ends the request, never owns routing,
 * - never silently swallows downstream errors (they propagate),
 * - determines the secure context from the TLS socket / `req.secure`
 *   (Express `trust proxy`), never from `X-Forwarded-Proto` directly,
 * - honors `overwrite: false` against headers already set on the
 *   response at middleware time.
 *
 * @module headers/middleware
 */

import type { HeaderBuildContext, SecurityHeadersMiddleware } from "./types";
import type { ResolvedSecurityHeadersConfig } from "./config";

/**
 * Creates the middleware for a resolved configuration.
 *
 * @param config - Fully-resolved configuration.
 * @param build - The pure engine function (`buildHeaderSet`).
 * @returns The Connect/Express-style middleware.
 */
export function createMiddleware(
  config: ResolvedSecurityHeadersConfig,
  build: (context: HeaderBuildContext) => ReturnType<typeof import("./core").buildHeaderSet>
): SecurityHeadersMiddleware {
  return (req, res, next) => {
    const finish = (error?: unknown): void => {
      if (error) {
        if (next) next(error);
        else throw error;
        return;
      }
      next?.();
    };

    try {
      // Express sets `req.secure` from its `trust proxy` configuration;
      // raw node exposes the TLS state on `req.socket.encrypted`.
      // `X-Forwarded-Proto` is intentionally ignored: trusting it without
      // a proxy that strips it is a spoofing vector.
      const secure = req.secure === true || req.socket?.encrypted === true;

      const existing = res.getHeaders?.() ?? {};
      const plan = build({ secure, existing });

      for (const name of plan.removed) {
        res.removeHeader?.(name);
      }
      for (const [name, value] of Object.entries(plan.headers)) {
        res.setHeader(name, value);
      }
    } catch (error) {
      finish(error);
      return;
    }

    finish();
  };
}