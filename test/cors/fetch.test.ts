import { describe, expect, test } from "bun:test";
import { Cors } from "../../src/cors/index";

const request = (method: string, headers: Record<string, string>): Request =>
  new Request(`https://api.example.com/data`, { method, headers });

describe("CORS fetch handler - CORS-only adapter", () => {
  test("answers preflights and returns nothing for simple requests", async () => {
    const handle = Cors({ origin: ["https://app.example.com"], credentials: true }).fetchHandler();

    const preflight = await handle(
      request("OPTIONS", {
        origin: "https://app.example.com",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      })
    );
    expect(preflight?.status).toBe(204);
    expect(preflight?.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example.com");
    expect(preflight?.headers.get("Access-Control-Allow-Credentials")).toBe("true");
    expect(preflight?.headers.get("Access-Control-Allow-Headers")).toBe("content-type");
    expect(preflight?.headers.get("Vary")).toContain("Origin");

    const simple = await handle(request("GET", { origin: "https://app.example.com" }));
    expect(simple).toBeUndefined();
  });

  test("denied preflights are rejected with 403", async () => {
    const handle = Cors({ origin: ["https://app.example.com"] }).fetchHandler();
    const response = await handle(
      request("OPTIONS", { origin: "https://evil.com", "access-control-request-method": "GET" })
    );
    expect(response?.status).toBe(403);
    expect(response?.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});

describe("CORS fetch handler - with a wrapped handler", () => {
  test("merges CORS headers into the handler response", async () => {
    const handle = Cors({ exposedHeaders: ["x-total"] }).fetchHandler(
      (req) =>
        new Response("ok", {
          status: 200,
          headers: { "content-type": "application/json" },
        })
    );

    const response = await handle(request("GET", { origin: "https://app.example.com" }));
    expect(response?.status).toBe(200);
    expect(await response?.text()).toBe("ok");
    expect(response?.headers.get("content-type")).toBe("application/json");
    expect(response?.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(response?.headers.get("Access-Control-Expose-Headers")).toBe("x-total");
    expect(response?.headers.get("Vary")).toBe("Origin");
  });

  test("intercepts preflights before reaching the wrapped handler", async () => {
    let handlerCalled = false;
    const handle = Cors({}).fetchHandler((req) => {
      handlerCalled = true;
      return new Response("should not happen", { status: 200 });
    });

    const response = await handle(
      request("OPTIONS", { origin: "https://app.example.com", "access-control-request-method": "PUT" })
    );
    expect(handlerCalled).toBe(false);
    expect(response?.status).toBe(204);
  });

  test("hard-blocked requests never invoke the wrapped handler", async () => {
    let handlerCalled = false;
    const handle = Cors({ origin: ["https://app.example.com"], failureStatus: 403 }).fetchHandler(
      (req) => {
        handlerCalled = true;
        return new Response("nope", { status: 200 });
      }
    );

    const response = await handle(request("GET", { origin: "https://evil.com" }));
    expect(handlerCalled).toBe(false);
    expect(response?.status).toBe(403);
  });
});

describe("CORS fetch handler - async origins", () => {
  test("callback-based origins resolve through processAsync", async () => {
    const handle = Cors({
      origin: (origin, callback) => {
        callback(null, origin === "https://allowed.example.com");
      },
    }).fetchHandler((req) => new Response("ok", { status: 200 }));

    const allowed = await handle(request("GET", { origin: "https://allowed.example.com" }));
    expect(allowed?.headers.get("Access-Control-Allow-Origin")).toBe("https://allowed.example.com");

    const denied = await handle(request("GET", { origin: "https://denied.example.com" }));
    expect(denied?.status).toBe(403);
  });

  test("callback origins may reflect a concrete origin string", async () => {
    const handle = Cors({
      origin: (_origin, callback) => callback(null, "https://mirror.example.com"),
    }).fetchHandler((req) => new Response("ok", { status: 200 }));

    const response = await handle(request("GET", { origin: "https://anything.example.com" }));
    expect(response?.headers.get("Access-Control-Allow-Origin")).toBe("https://mirror.example.com");
  });
});