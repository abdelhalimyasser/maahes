import { describe, expect, test } from "bun:test";
import { Cors } from "../../src/cors/index";
import type { CorsHeadersInput, ServerResponseLike } from "../../src/cors/types";

const makeResponse = () => {
  const headers: Record<string, string> = {};
  const res: {
    setHeader: (name: string, value: string) => void;
    statusCode: number;
    ended: boolean;
  } & ServerResponseLike = {
    setHeader: (name, value) => {
      headers[name] = value;
    },
    statusCode: 200,
    ended: false,
    end: () => {
      res.ended = true;
      return undefined;
    },
  };
  return { res, headers };
};

const req = (method?: string, headers?: CorsHeadersInput) => ({ method, headers });

describe("CORS middleware - Express style", () => {
  test("expresses through next() after decorating a simple request", () => {
    const middleware = Cors({ origin: ["https://app.example.com"], credentials: true }).middleware();
    const { res, headers } = makeResponse();
    let called = false;

    middleware(req("GET", { origin: "https://app.example.com" }), res, () => {
      called = true;
    });

    expect(called).toBe(true);
    expect(res.ended).toBe(false);
    expect(headers["Access-Control-Allow-Origin"]).toBe("https://app.example.com");
    expect(headers["Access-Control-Allow-Credentials"]).toBe("true");
  });

  test("answers preflights with the options status and does not call next", () => {
    const middleware = Cors({}).middleware();
    const { res, headers } = makeResponse();
    let called = false;

    middleware(
      req("OPTIONS", {
        origin: "https://app.example.com",
        "access-control-request-method": "DELETE",
      }),
      res,
      () => {
        called = true;
      }
    );

    expect(called).toBe(false);
    expect(res.ended).toBe(true);
    expect(res.statusCode).toBe(204);
    expect(headers["Access-Control-Allow-Methods"]).toBe("GET, HEAD, PUT, PATCH, POST, DELETE");
  });

  test("hard-blocked requests end with the configured status", () => {
    const middleware = Cors({ origin: ["https://app.example.com"], failureStatus: 403 }).middleware();
    const { res } = makeResponse();
    let called = false;

    middleware(req("GET", { origin: "https://evil.com" }), res, () => {
      called = true;
    });

    expect(called).toBe(false);
    expect(res.ended).toBe(true);
    expect(res.statusCode).toBe(403);
  });

  test("omitted-header blocks pass through without ending", () => {
    const middleware = Cors({ origin: ["https://app.example.com"] }).middleware();
    const { res, headers } = makeResponse();
    let called = false;

    middleware(req("GET", { origin: "https://evil.com" }), res, () => {
      called = true;
    });

    expect(called).toBe(true);
    expect(res.ended).toBe(false);
    expect(Object.keys(headers)).toHaveLength(0);
  });
});

describe("CORS middleware - raw node:http style (no next)", () => {
  test("preflights are ended by the CORS layer alone", () => {
    const handler = Cors({}).middleware();
    const { res, headers } = makeResponse();

    handler(req("OPTIONS", { origin: "https://app.example.com", "access-control-request-method": "GET" }), res);

    expect(res.ended).toBe(true);
    expect(headers["Access-Control-Allow-Origin"]).toBe("*");
  });

  test("simple requests are decorated without ending", () => {
    const handler = Cors({}).middleware();
    const { res, headers } = makeResponse();

    handler(req("GET", { origin: "https://app.example.com" }), res);

    expect(res.ended).toBe(false);
    expect(headers["Access-Control-Allow-Origin"]).toBe("*");
  });

  test("hard blocks map to failureStatus", () => {
    const handler = Cors({ origin: ["https://app.example.com"], failureStatus: 403 }).middleware();
    const { res } = makeResponse();

    handler(req("GET", { origin: "https://evil.com" }), res);

    expect(res.ended).toBe(true);
    expect(res.statusCode).toBe(403);
  });
});