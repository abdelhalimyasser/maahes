import { describe, expect, test } from "bun:test";
import { SecurityHeaders, SecurityHeadersOptionsError } from "../../src/headers/index";

describe("headers adversarial: injection and tampering", () => {
  test("CRLF / response splitting is rejected in every configurable value", () => {
    const payloads = [
      "x\r\nSet-Cookie: pwned=1",
      "x\nSet-Cookie: pwned=1",
      "x\rSet-Cookie: pwned=1",
      "x\u0000y",
      "x\u0007y",
      "x\u001Fy",
      "x\u007Fy",
      "\u0008",
      "value\u000Amore",
    ];
    for (const payload of payloads) {
      expect(() => SecurityHeaders({ extra: { "X-Evil": payload } })).toThrow(SecurityHeadersOptionsError);
    }
  });

  test("header names with spaces, colons or control chars are rejected", () => {
    for (const name of ["Bad Name", "Bad:Name", "Bad\u000AName", "Bad\u000DName", "", " ", "X\u0000Y"]) {
      expect(() => SecurityHeaders({ extra: { [name]: "v" } })).toThrow(SecurityHeadersOptionsError);
    }
  });

  test("hostile remove entries are rejected", () => {
    for (const name of ["S\re", "S\nr", "S r", "", "X\u0000Y", "Connection: close"]) {
      expect(() => SecurityHeaders({ remove: [name] })).toThrow(SecurityHeadersOptionsError);
    }
  });

  test("tab and SP are legal in header values (RFC 7230)", () => {
    const { headers } = SecurityHeaders({ extra: { "X-Tab": "a\tb" } }).build();
    expect(headers["X-Tab"]).toBe("a\tb");
  });

  test("permissionsPolicy cannot smuggle directives", () => {
    expect(() =>
      SecurityHeaders({ permissionsPolicy: 'camera=(),\r\nX-Evil: 1' as never })
    ).toThrow(SecurityHeadersOptionsError);
  });

  test("no header value ever contains a newline in the final plan", () => {
    const { headers } = SecurityHeaders({ preset: "strict", extra: { "X-Fine": "ok" } }).build();
    for (const value of Object.values(headers)) {
      expect(value).not.toMatch(/[\r\n\u0000-\u001F\u007F]/);
    }
  });
});

describe("headers adversarial: HSTS misuse", () => {
  test("huge maxAge and tiny maxAge are both accepted with correct bounds", () => {
    expect(SecurityHeaders({ hsts: { maxAge: 0 } }).build({ secure: true }).headers["Strict-Transport-Security"]).toBe(
      "max-age=0; includeSubDomains"
    );
    expect(
      SecurityHeaders({ hsts: { maxAge: 631138519 } }).build({ secure: true }).headers["Strict-Transport-Security"]
    ).toBe("max-age=631138519; includeSubDomains");
    expect(() => SecurityHeaders({ hsts: { maxAge: 631138520 } })).toThrow(SecurityHeadersOptionsError);
  });

  test("preload without the required preconditions fails fast", () => {
    for (const bad of [
      { maxAge: 31536000, includeSubDomains: true, preload: 1 },
      { maxAge: 31536000, includeSubDomains: true, preload: "yes" },
    ]) {
      expect(() => SecurityHeaders({ hsts: bad as never })).toThrow(SecurityHeadersOptionsError);
    }
  });

  test("HSTS is never served over an insecure context unless explicitly allowed", () => {
    const module = SecurityHeaders();
    expect(module.build({ secure: false }).headers["Strict-Transport-Security"]).toBeUndefined();
    const bare = SecurityHeaders({ httpsOnly: false });
    expect(bare.build({ secure: false }).headers["Strict-Transport-Security"]).toBe(
      "max-age=31536000; includeSubDomains"
    );
  });
});

describe("headers adversarial: cross-origin isolation mistakes", () => {
  test("strict preset demands CORP same-origin so cross-origin isolation holds", () => {
    const { headers } = SecurityHeaders({ preset: "strict" }).build();
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(headers["Cross-Origin-Embedder-Policy"]).toBe("credentialless");
    expect(headers["Cross-Origin-Resource-Policy"]).toBe("same-origin");
  });

  test("coop/coep values are constrained to the standard set", () => {
    for (const coop of ["unsafe-none", "same-origin", "same-origin-allow-popups"] as const) {
      expect(SecurityHeaders({ coop }).build().headers["Cross-Origin-Opener-Policy"]).toBe(coop);
    }
    for (const coep of ["unsafe-none", "require-corp", "credentialless"] as const) {
      expect(SecurityHeaders({ coep }).build().headers["Cross-Origin-Embedder-Policy"]).toBe(coep);
    }
    expect(() => SecurityHeaders({ coop: "same-origin; same-site" as never })).toThrow(SecurityHeadersOptionsError);
    expect(() => SecurityHeaders({ coep: "credentialless, require-corp" as never })).toThrow(SecurityHeadersOptionsError);
  });
});

describe("headers adversarial: determinism and purity under hostility", () => {
  test("config objects are never mutated by resolution or build", () => {
    const frozen = Object.freeze({
      preset: "strict" as const,
      extra: Object.freeze({ "X-A": "1" }),
      remove: Object.freeze(["Server"]),
    });
    expect(() => SecurityHeaders(frozen)).not.toThrow();
    const module = SecurityHeaders(frozen);
    const existing = Object.freeze({ "X-Frame-Options": "SAMEORIGIN" });
    expect(() => module.build({ existing })).not.toThrow();
  });

  test("weird-but-legal names/values round-trip exactly", () => {
    const module = SecurityHeaders({ extra: { "X-Weird_~.`": "1;2,3 4\t5" } });
    const { headers } = module.build();
    expect(headers["X-Weird_~.`"]).toBe("1;2,3 4\t5");
  });

  test("known headers cannot be spoofed via extra (case-insensitively)", () => {
    expect(() => SecurityHeaders({ extra: { "x-frame-options": "SAMEORIGIN" } })).toThrow(
      SecurityHeadersOptionsError
    );
    expect(() => SecurityHeaders({ extra: { "X-CONTENT-TYPE-OPTIONS": "nosniff" } })).toThrow(
      SecurityHeadersOptionsError
    );
    // The engine's own headers are configured via their keys, never extras.
  });

  test("the same headers object is returned with stable ordering across builds", () => {
    const module = SecurityHeaders({ preset: "minimal", extra: { "M-1": "1", "A-1": "2" } });
    const first = Object.keys(module.build().headers);
    const second = Object.keys(module.build().headers);
    expect(first).toEqual(second);
    // Known headers precede extras; extras sorted among themselves.
    expect(first.slice(-2)).toEqual(["A-1", "M-1"]);
  });
});

describe("headers adversarial: adapter boundaries", () => {
  test("middleware never touches the request object", () => {
    const req = Object.freeze({ socket: Object.freeze({ encrypted: true }) });
    const res = { setHeader() {}, removeHeader() {}, getHeaders: () => ({}) };
    expect(() => SecurityHeaders().middleware()(req, res as never, () => {})).not.toThrow();
  });

  test("middleware tolerates an existing-headers-less response", () => {
    const res = { setHeader() {}, removeHeader() {} };
    expect(() => SecurityHeaders().middleware()({} as never, res as never, () => {})).not.toThrow();
  });

  test("fetch wrapper tolerates null bodies and redirects", async () => {
    const wrapped = SecurityHeaders().fetchHandler(() => new Response(null, { status: 204 }));
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");

    const redirected = SecurityHeaders().fetchHandler(
      () => Response.redirect("https://api.example.com/next", 302)
    );
    const redir = await redirected(new Request("https://api.example.com/"));
    expect(redir.status).toBe(302);
    expect(redir.headers.get("Location")).toBe("https://api.example.com/next");
    expect(redir.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});