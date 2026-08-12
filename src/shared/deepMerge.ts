/**
 * @fileoverview Shared configuration merging utilities.
 *
 * @module shared/deepMerge
 */

/**
 * Recursively merges `overrides` into `defaults`.
 * - Any field missing/undefined in `overrides` falls back to `defaults`.
 * - Nested objects are merged field-by-field (not replaced wholesale).
 * - Arrays and primitives in `overrides` fully replace the default value
 *   (arrays are NOT merged element-by-element - that's rarely what you want
 *   for things like `blockedPasswords` or `allowedScripts`).
 *
 * This is the single merge function every module's config should use,
 * so "missing field -> use default" behavior is consistent everywhere.
 */
export function deepMerge<T extends Record<string, unknown>>(
  defaults: T,
  overrides: Partial<T> = {}
): T {
  const result: Record<string, unknown> = { ...defaults };

  for (const key of Object.keys(overrides) as Array<keyof T>) {
    const overrideValue = overrides[key];
    const defaultValue = defaults[key];

    if (overrideValue === undefined) continue; // explicit undefined -> keep default

    const isPlainObject = (v: unknown): v is Record<string, unknown> =>
      typeof v === 'object' && v !== null && !Array.isArray(v);

    if (isPlainObject(overrideValue) && isPlainObject(defaultValue)) {
      result[key as string] = deepMerge(
        defaultValue as Record<string, unknown>,
        overrideValue as Record<string, unknown>
      );
    } else {
      result[key as string] = overrideValue; // arrays & primitives: override wins fully
    }
  }

  return result as T;
}