/**
 * @fileoverview Security headers error types.
 *
 * @module headers/errors
 */

import { MaahesOptionsError } from "../shared/errors";

/**
 * Thrown at construction time when a security headers option is invalid:
 * unknown preset, malformed header name, CR/LF/NUL in a header value,
 * impossible HSTS combination, unknown enum value, etc. Failing fast
 * here guarantees the engine can never emit a dangerous or
 * response-splitting header set.
 */
export class SecurityHeadersOptionsError extends MaahesOptionsError {
  constructor(message: string) {
    super(message);
    this.name = "SecurityHeadersOptionsError";
  }
}