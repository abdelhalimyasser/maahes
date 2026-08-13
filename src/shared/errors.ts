/**
 * @fileoverview Shared error base classes for every Maahes module.
 *
 * All module-specific errors derive from {@link MaahesError}, so
 * applications can catch configuration and runtime failures uniformly
 * (`err instanceof MaahesError`) while still discriminating per module
 * through the concrete class names.
 *
 * Error contract (enforced across the library):
 * - stable `name` per class (never the generic `"Error"`),
 * - actionable messages naming the offending option and its range,
 * - NEVER include secrets: no passwords, no pepper secrets, no
 *   configuration dumps containing them.
 *
 * @module shared/errors
 */

/** Base class of every Maahes error. */
export class MaahesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MaahesError";
  }
}

/**
 * Base class of every configuration error raised at module construction
 * time (fail-fast validation). Extending it keeps `instanceof`
 * discrimination per module intact.
 */
export class MaahesOptionsError extends MaahesError {
  constructor(message: string) {
    super(message);
    this.name = "MaahesOptionsError";
  }
}