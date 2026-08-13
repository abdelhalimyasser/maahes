/**
 * @fileoverview Password policy engine: built-in validation rules, custom
 * rules, entropy estimation and the {@link PasswordPolicyError} type.
 *
 * All regular expressions are hoisted to module scope and compiled once.
 * Per-instance artifacts (combined script whitelist regex, blocklist `Set`)
 * are built once per policy object and cached with a `WeakMap`, so
 * `validatePassword` performs zero allocation-heavy setup per call.
 *
 * @module password/policy
 */

import type {
  CustomPasswordRule,
  PasswordPolicyOptions,
  PasswordScript,
  PolicyResult,
  PolicyViolation,
} from "./types";
import { MaahesError } from "../shared/errors";

/** Matches any letter of the Arabic script. */
const ARABIC_RE = /\p{Script=Arabic}/u;
/** Matches any letter of the Cyrillic script. */
const CYRILLIC_RE = /\p{Script=Cyrillic}/u;
/** Matches any letter of the Greek script. */
const GREEK_RE = /\p{Script=Greek}/u;
/** Matches any letter of the Han (Chinese) script. */
const HAN_RE = /\p{Script=Han}/u;
/** Matches any letter of the Latin script. */
const LATIN_RE = /\p{Script=Latin}/u;

/** Matches any Unicode letter (used to identify script-carrying characters). */
const LETTER_RE = /\p{L}/u;
/** Matches any whitespace character. */
const WHITESPACE_RE = /\s/u;
/** Matches any lowercase letter. */
const LOWERCASE_RE = /\p{Ll}/u;
/** Matches any uppercase letter. */
const UPPERCASE_RE = /\p{Lu}/u;
/** Matches any ASCII digit. */
const DIGIT_RE = /[0-9]/;
/** Matches any symbol (punctuation or other symbol, excluding letters, numbers and whitespace). */
const SYMBOL_RE = /[^\p{L}\p{N}\s]/u;

/** Global variants used for counting occurrences; safe with `String.prototype.match`. */
const LOWERCASE_COUNT_RE = /\p{Ll}/gu;
const UPPERCASE_COUNT_RE = /\p{Lu}/gu;
const DIGIT_COUNT_RE = /[0-9]/g;
const SYMBOL_COUNT_RE = /[^\p{L}\p{N}\s]/gu;

/** Script name -> matcher for the supported writing systems. */
const SCRIPT_REGEX: Record<Exclude<PasswordScript, "Any">, RegExp> = {
  Latin: LATIN_RE,
  Arabic: ARABIC_RE,
  Cyrillic: CYRILLIC_RE,
  Greek: GREEK_RE,
  Han: HAN_RE,
};

/** Internal, precomputed policy representation used by the validator. */
interface CompiledPolicy {
  minLength: number;
  maxLength: number;
  blockWhitespace: boolean;
  minUppercase: number;
  minLowercase: number;
  minDigits: number;
  minSymbols: number;
  minEntropy: number;
  /** Combined regex matching a letter of ANY allowed script; `null` when the check is disabled. */
  allowedScriptsRegex: RegExp | null;
  /** Lower-cased blocklist for O(1) exact-match lookups. */
  blockedSet: Set<string>;
  customRules: CustomPasswordRule[];
}

/** Memoizes {@link compilePolicy} per policy object reference. */
const compiledCache = new WeakMap<Required<PasswordPolicyOptions>, CompiledPolicy>();

/**
 * Compiles a fully-resolved policy into fast, immutable validation state.
 * Results are cached per policy object, so repeated validation calls with
 * the same module instance reuse the compiled artifacts.
 *
 * @param policy - Fully-resolved (defaults-merged) policy options.
 * @returns The compiled policy.
 */
function compilePolicy(policy: Required<PasswordPolicyOptions>): CompiledPolicy {
  const cached = compiledCache.get(policy);
  if (cached) return cached;

  const allowedScripts = policy.allowedScripts.filter(
    (script): script is Exclude<PasswordScript, "Any"> => script !== "Any"
  );

  const compiled: CompiledPolicy = {
    minLength: policy.minLength,
    maxLength: policy.maxLength,
    blockWhitespace: policy.blockWhitespace,
    minUppercase: policy.minUppercase,
    minLowercase: policy.minLowercase,
    minDigits: policy.minDigits,
    minSymbols: policy.minSymbols,
    minEntropy: policy.minEntropy,
    allowedScriptsRegex:
      allowedScripts.length > 0
        ? new RegExp(`[${allowedScripts.map((s) => `\\p{Script=${s}}`).join("")}]`, "u")
        : null,
    blockedSet: new Set(policy.blockedPasswords.map((p) => p.toLowerCase())),
    customRules: policy.customRules,
  };

  compiledCache.set(policy, compiled);
  return compiled;
}

/**
 * Thrown by `hashPassword()` / `pepperedHashPassword()` when
 * `policy.enforceOnHash` is enabled and the candidate password violates
 * the policy. Carries the structured violation list for error reporting.
 */
export class PasswordPolicyError extends MaahesError {
  /** Every violated rule, in evaluation order. */
  violations: PolicyViolation[];

  /**
   * @param violations - The violations that caused the rejection.
   */
  constructor(violations: PolicyViolation[]) {
    super(`Password does not meet policy requirements: ${violations.map((v) => v.rule).join(", ")}`);
    this.name = "PasswordPolicyError";
    this.violations = violations;
  }
}

/**
 * Estimates the entropy of a password in bits using character-class pool
 * analysis: `length * log2(pool)` where `pool` is the union of the
 * character classes observed (lowercase, uppercase, digits, symbols,
 * non-ASCII letters, whitespace).
 *
 * This is a fast heuristic for policy gating (e.g. rejecting
 * `minEntropy`), NOT a substitute for measuring real-world password
 * strength (sequences, dictionary words and repetition inflate the score).
 *
 * @param password - The candidate password.
 * @returns Estimated entropy in bits (`0` for an empty password).
 */
export function estimateEntropy(password: string): number {
  const length = [...password].length;
  if (length === 0) return 0;

  let pool = 0;
  if (LOWERCASE_RE.test(password)) pool += 26;
  if (UPPERCASE_RE.test(password)) pool += 26;
  if (DIGIT_RE.test(password)) pool += 10;
  if (SYMBOL_RE.test(password)) pool += 33;
  if ([...password].some((ch) => LETTER_RE.test(ch) && !/[a-zA-Z]/.test(ch))) pool += 100;
  if (WHITESPACE_RE.test(password)) pool += 10;

  return Math.round(length * Math.log2(pool));
}

/**
 * Validates a password against a fully-resolved policy. Purely
 * functional: never throws, does not hash, and reports every violated
 * rule instead of failing on the first one.
 *
 * Lengths are measured in Unicode code points, so multi-code-point
 * characters (e.g. emoji) count once rather than twice.
 *
 * @param password - The candidate password.
 * @param policy - Fully-resolved policy options (all fields present).
 * @returns The validity verdict plus all violations.
 */
export function validatePassword(
  password: string,
  policy: Required<PasswordPolicyOptions>
): PolicyResult {
  const compiled = compilePolicy(policy);
  const violations: PolicyViolation[] = [];
  const length = [...password].length;

  if (length < compiled.minLength) {
    violations.push({
      rule: "minLength",
      message: `Password must be at least ${compiled.minLength} characters.`,
    });
  }
  if (length > compiled.maxLength) {
    violations.push({
      rule: "maxLength",
      message: `Password must be at most ${compiled.maxLength} characters.`,
    });
  }
  if (compiled.blockWhitespace && WHITESPACE_RE.test(password)) {
    violations.push({ rule: "whitespace", message: "Password must not contain whitespace." });
  }

  const uppercaseCount = (password.match(UPPERCASE_COUNT_RE) ?? []).length;
  const lowercaseCount = (password.match(LOWERCASE_COUNT_RE) ?? []).length;
  const digitCount = (password.match(DIGIT_COUNT_RE) ?? []).length;
  const symbolCount = (password.match(SYMBOL_COUNT_RE) ?? []).length;

  if (uppercaseCount < compiled.minUppercase) {
    violations.push({
      rule: "minUppercase",
      message: `Password must contain at least ${compiled.minUppercase} uppercase letter(s).`,
    });
  }
  if (lowercaseCount < compiled.minLowercase) {
    violations.push({
      rule: "minLowercase",
      message: `Password must contain at least ${compiled.minLowercase} lowercase letter(s).`,
    });
  }
  if (digitCount < compiled.minDigits) {
    violations.push({
      rule: "minDigits",
      message: `Password must contain at least ${compiled.minDigits} digit(s).`,
    });
  }
  if (symbolCount < compiled.minSymbols) {
    violations.push({
      rule: "minSymbols",
      message: `Password must contain at least ${compiled.minSymbols} symbol character(s).`,
    });
  }

  if (compiled.minEntropy > 0 && estimateEntropy(password) < compiled.minEntropy) {
    violations.push({
      rule: "minEntropy",
      message: `Password's estimated entropy is below the required minimum of ${compiled.minEntropy} bits.`,
    });
  }

  if (compiled.allowedScriptsRegex) {
    for (const char of password) {
      if (!LETTER_RE.test(char)) continue; // digits/symbols/spaces are script-agnostic
      if (!compiled.allowedScriptsRegex.test(char)) {
        violations.push({
          rule: "allowedScripts",
          message: `Password contains characters outside the allowed scripts: ${policy.allowedScripts.join(", ")}.`,
        });
        break;
      }
    }
  }

  if (compiled.blockedSet.has(password.toLowerCase())) {
    violations.push({ rule: "blockedPasswords", message: "This password is too common and not allowed." });
  }

  for (const rule of compiled.customRules) {
    if (!rule.test(password, policy)) {
      violations.push({
        rule: rule.rule,
        message: rule.message ?? `Password failed custom rule "${rule.rule}".`,
      });
    }
  }

  return { valid: violations.length === 0, violations };
}