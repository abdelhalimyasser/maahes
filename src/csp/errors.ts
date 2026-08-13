/**
 * @fileoverview CSP module error types.
 *
 * @module csp/errors
 */

import { MaahesOptionsError } from "../shared/errors";

/**
 * Thrown at construction (and at build time for nonce mismatches) when a
 * CSP option, directive or source expression is invalid. Extends the
 * shared `MaahesOptionsError` base so a single `instanceof MaahesError`
 * check covers the whole toolkit.
 */
export class CspOptionsError extends MaahesOptionsError {
  constructor(message: string) {
    super(message);
    this.name = "CspOptionsError";
  }
}