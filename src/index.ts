/**
 * @fileoverview Maahes security toolkit - root entry point.
 *
 * The password module is the currently-shipping feature. Additional
 * security modules (CORS, CSRF, CSP, headers, hashing, encryption,
 * rate limiting, secrets, XSS, SQL injection, audit) are planned and
 * will be exported from here as they land.
 *
 * @module maahes
 */

export * from "./password";
export { Password as default } from "./password";