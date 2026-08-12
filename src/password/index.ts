/**
 * @fileoverview Public barrel of the Maahes password module.
 *
 * Re-exports the full public surface: the {@link Password} factory
 * (default export), hash-format detection, the policy engine, config
 * defaults/errors and every public type.
 *
 * @module password
 */

export * from "./config";
export * from "./detect";
export * from "./factory";
export * from "./policy";
export * from "./types";
export { Password as default } from "./factory";