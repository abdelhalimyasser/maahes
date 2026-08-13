import { describe, expect, test } from "bun:test";
import { SecurityHeaders, buildHeaderSet, KNOWN_HEADER_ORDER } from "../../src/headers/index";
import type { SecurityHeadersConfig } from "../../src/headers/index";

const DEFAULTS: SecurityHeadersConfig = {};

describe("headers core: emission", () => {
  test("default config emits the full default header set in canonical order", () => {
    const { headers } = SecurityHeaders(DEFAULTS).build({ secure: true });
    const keys = Object.keys(headers);
    expect(headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(headers["Cross-Origin-Embedder-Policy"]).toBe("credentialless");
    expect(headers["Permissions-Policy"]).toBe("camera=(), microphone=(), geolocation=()");
    expect(headers["X-XSS-Protection"]).toBe("0");
    expect(headers["X-Permitted-Cross-Domain-Policies"]).toBe("none");
    expect(headers["Cross-Origin-Resource-Policy"]).toBeUndefined();

    // Canonical order: known headers first, in fixed order.
    const known = keys.filter((k) => KNOWN_HEADER_ORDER.includes(k as (typeof KNOWN_HEADER_ORDER)[number]));
    expect(known).toEqual(KNOWN_HEADER_ORDER.filter((k) => known.includes(k)));
  });

  test("CSP is NEVER emitted by this module", () => {
    const { headers } = SecurityHeaders({ preset: "strict" }).build();
    expect(headers["Content-Security-Policy"]).toBeUndefined();
    expect(Object.keys(headers).some((k) => k.toLowerCase() === "content-security-policy")).toBe(false);
  });

  test("headers are disable-able with false", () => {
    const { headers } = SecurityHeaders({
      nosniff: false,
      frameOptions: false,
      referrerPolicy: false,
      hsts: false,
      coop: false,
      coep: false,
      permissionsPolicy: false,
      xssProtection: false,
      crossDomainPolicy: false,
    }).build({ secure: true });
    expect(headers).toEqual({});
  });

  test("strict preset emits CORP same-origin and no-referrer", () => {
    const { headers } = SecurityHeaders({ preset: "strict" }).build({ secure: true });
    expect(headers["Cross-Origin-Resource-Policy"]).toBe("same-origin");
    expect(headers["Referrer-Policy"]).toBe("no-referrer");
  });

  test("xssProtection is typed, never an ambiguous boolean", () => {
    expect(SecurityHeaders({ xssProtection: "0" }).build().headers["X-XSS-Protection"]).toBe("0");
    expect(SecurityHeaders({ xssProtection: "1; mode=block" }).build().headers["X-XSS-Protection"]).toBe("1; mode=block");
    expect(SecurityHeaders({ xssProtection: false }).build().headers["X-XSS-Protection"]).toBeUndefined();
  });

  test("optional hardening headers are opt-in", () => {
    const off = SecurityHeaders().build();
    expect(off.headers["X-DNS-Prefetch-Control"]).toBeUndefined();
    expect(off.headers["Origin-Agent-Cluster"]).toBeUndefined();
    const on = SecurityHeaders({ dnsPrefetchControl: true, originAgentCluster: true }).build();
    expect(on.headers["X-DNS-Prefetch-Control"]).toBe("off");
    expect(on.headers["Origin-Agent-Cluster"]).toBe("?1");
  });
});

describe("headers core: HSTS semantics", () => {
  test("HSTS is emitted in secure contexts (build assumes secure by default)", () => {
    const hsts = SecurityHeaders().build().headers["Strict-Transport-Security"];
    expect(hsts).toBe("max-age=31536000; includeSubDomains");
  });

  test("httpsOnly: true suppresses HSTS in insecure contexts", () => {
    const insecure = SecurityHeaders().build({ secure: false });
    expect(insecure.headers["Strict-Transport-Security"]).toBeUndefined();
    expect(insecure.headers["X-Content-Type-Options"]).toBe("nosniff"); // others stay
  });

  test("httpsOnly: false emits HSTS regardless of context", () => {
    const insecure = SecurityHeaders({ httpsOnly: false }).build({ secure: false });
    expect(insecure.headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");
  });

  test("custom HSTS values and preload rendering", () => {
    const custom = SecurityHeaders({ hsts: { maxAge: 63072000, includeSubDomains: true, preload: true } }).build({
      secure: true,
    });
    expect(custom.headers["Strict-Transport-Security"]).toBe(
      "max-age=63072000; includeSubDomains; preload"
    );
    const noSub = SecurityHeaders({ hsts: { maxAge: 3600, includeSubDomains: false } }).build({ secure: true });
    expect(noSub.headers["Strict-Transport-Security"]).toBe("max-age=3600");
  });
});

describe("headers core: overwrite and remove semantics", () => {
  test("overwrite: true (default) replaces same-named existing headers", () => {
    const { headers } = SecurityHeaders().build({
      secure: true,
      existing: { "x-frame-options": "SAMEORIGIN", "X-Custom": "keep" },
    });
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["X-Custom"]).toBe("keep");
    expect(Object.keys(headers).filter((k) => k.toLowerCase() === "x-frame-options")).toHaveLength(1);
  });

  test("overwrite: false lets existing application headers win", () => {
    const { headers } = SecurityHeaders({ overwrite: false }).build({
      secure: true,
      existing: { "X-Frame-Options": "SAMEORIGIN" },
    });
    expect(headers["X-Frame-Options"]).toBe("SAMEORIGIN");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff"); // absent ones are still added
  });

  test("remove drops existing headers case-insensitively", () => {
    const { headers, removed } = SecurityHeaders({ remove: ["Server", "x-powered-by"] }).build({
      existing: { Server: "nginx", "X-Powered-By": "Express", "X-Keep": "1" },
    });
    expect(headers["Server"]).toBeUndefined();
    expect(headers["X-Powered-By"]).toBeUndefined();
    expect(headers["X-Keep"]).toBe("1");
    expect(removed).toEqual(["Server", "x-powered-by"]);
  });

  test("remove targets existing runtime headers only; own headers are governed by config keys", () => {
    const { headers } = SecurityHeaders({ remove: ["x-frame-options"] }).build({
      existing: { "X-Frame-Options": "SAMEORIGIN" },
    });
    // The existing header is removed and not re-added, but the engine's own
    // X-Frame-Options (frameOptions: "DENY") is unaffected by `remove`.
    expect(headers["X-Frame-Options"]).toBe("DENY");
    // The documented way to suppress the engine's own header is its config key.
    expect(SecurityHeaders({ frameOptions: false }).build().headers["X-Frame-Options"]).toBeUndefined();
  });
});

describe("headers core: extras", () => {
  test("extras are emitted sorted deterministically", () => {
    const { headers } = SecurityHeaders({
      extra: { "Z-Header": "z", "A-Header": "a", "M-Header": "m" },
    }).build();
    const keys = Object.keys(headers);
    const extraKeys = keys.filter((k) => k.endsWith("-Header"));
    expect(extraKeys).toEqual(["A-Header", "M-Header", "Z-Header"]);
  });

  test("extras never allow response splitting (validated at construction)", () => {
    expect(() => SecurityHeaders({ extra: { "X-1": "a\r\nSet-Cookie: pwned=1" } })).toThrow(
      /control characters/
    );
    expect(() => SecurityHeaders({ extra: { "X-1": "a\nb" } })).toThrow(/control characters/);
  });

  test("empty extra values are legal", () => {
    const { headers } = SecurityHeaders({ extra: { "X-Empty": "" } }).build();
    expect(headers["X-Empty"]).toBe("");
  });
});

describe("headers core: determinism", () => {
  test("identical config + context produce byte-identical plans", () => {
    const a = SecurityHeaders({ preset: "strict", extra: { "B": "2", "A": "1" }, remove: ["Server"] }).build({
      secure: true,
      existing: { Server: "x", "X-Other": "y" },
    });
    const b = SecurityHeaders({ preset: "strict", extra: { "B": "2", "A": "1" }, remove: ["Server"] }).build({
      secure: true,
      existing: { Server: "x", "X-Other": "y" },
    });
    expect(Object.entries(a.headers)).toEqual(Object.entries(b.headers));
    expect(a.removed).toEqual(b.removed);
  });

  test("existing header insertion order is preserved", () => {
    const { headers } = SecurityHeaders().build({ existing: { B: "2", A: "1" } });
    expect(Object.keys(headers).slice(0, 2)).toEqual(["B", "A"]);
  });
});

describe("headers core: buildHeaderSet purity", () => {
  test("buildHeaderSet does not mutate its inputs", () => {
    const config = resolveConfigForTest({ preset: "strict" });
    const existing = { "X-Frame-Options": "SAMEORIGIN", Server: "x" };
    const snapshot = JSON.stringify(existing);
    buildHeaderSet(config, { secure: true, existing });
    expect(JSON.stringify(existing)).toBe(snapshot);
  });

  test("accepts Headers instances and entry arrays as existing", () => {
    const viaHeaders = SecurityHeaders().build({ existing: new Headers({ "x-frame-options": "SAMEORIGIN" }) });
    expect(viaHeaders.headers["X-Frame-Options"]).toBe("DENY");
    const viaEntries = SecurityHeaders().build({
      existing: [["x-frame-options", "SAMEORIGIN"] as [string, string]],
    });
    expect(viaEntries.headers["X-Frame-Options"]).toBe("DENY");
  });
});

import { resolveHeadersConfig } from "../../src/headers/index";
function resolveConfigForTest(user: Parameters<typeof resolveHeadersConfig>[0]) {
  return resolveHeadersConfig(user);
}