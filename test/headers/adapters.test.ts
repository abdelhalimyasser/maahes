import { describe, expect, test } from "bun:test";
import { SecurityHeaders } from "../../src/headers/index";

function fakeRes(initial: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...initial };
  const calls: Array<[string, string]> = [];
  return {
    headers,
    calls,
    setHeader: (name: string, value: string) => {
      headers[name] = value;
      calls.push([name, value]);
    },
    removeHeader: (name: string) => {
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
      }
    },
    getHeaders: () => headers,
  };
}

describe("headers middleware", () => {
  test("decorates the response and always calls next()", () => {
    const res = fakeRes();
    let nextCalled = false;
    const middleware = SecurityHeaders().middleware();
    middleware({ method: "GET" }, res as never, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(res.headers["X-Content-Type-Options"]).toBe("nosniff");
    // A request with no TLS evidence is treated as insecure: no HSTS.
    expect(res.headers["Strict-Transport-Security"]).toBeUndefined();
  });

  test("never ends the request", () => {
    const res = fakeRes();
    const middleware = SecurityHeaders().middleware();
    middleware({}, res as never, () => {});
    expect(res).toBeTruthy();
  });

  test("secure context comes from req.secure / socket.encrypted", () => {
    const insecure = fakeRes();
    SecurityHeaders().middleware()({}, insecure as never, () => {});
    expect(insecure.headers["Strict-Transport-Security"]).toBeUndefined();

    const viaSocket = fakeRes();
    SecurityHeaders().middleware()({ socket: { encrypted: true } }, viaSocket as never, () => {});
    expect(viaSocket.headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");

    const viaExpress = fakeRes();
    SecurityHeaders().middleware()({ secure: true }, viaExpress as never, () => {});
    expect(viaExpress.headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");
  });

  test("X-Forwarded-Proto is NEVER trusted directly", () => {
    const res = fakeRes();
    // A spoofed X-Forwarded-Proto must not enable HSTS on a plain HTTP request.
    SecurityHeaders().middleware()(
      { headers: { "x-forwarded-proto": "https" } } as never,
      res as never,
      () => {}
    );
    expect(res.headers["Strict-Transport-Security"]).toBeUndefined();
  });

  test("overwrite: false respects headers already set on the response", () => {
    const res = fakeRes({ "X-Frame-Options": "SAMEORIGIN" });
    SecurityHeaders({ overwrite: false }).middleware()({}, res as never, () => {});
    expect(res.headers["X-Frame-Options"]).toBe("SAMEORIGIN");
  });

  test("overwrite: true replaces earlier headers", () => {
    const res = fakeRes({ "X-Frame-Options": "SAMEORIGIN" });
    SecurityHeaders().middleware()({}, res as never, () => {});
    expect(res.headers["X-Frame-Options"]).toBe("DENY");
  });

  test("remove strips headers from the response", () => {
    const res = fakeRes({ Server: "nginx", "X-Powered-By": "Express" });
    SecurityHeaders({ remove: ["Server", "x-powered-by"] }).middleware()({}, res as never, () => {});
    expect(res.headers["Server"]).toBeUndefined();
    expect(res.headers["X-Powered-By"]).toBeUndefined();
  });

  test("errors propagate through next(err), never silently swallowed", () => {
    let captured: unknown;
    const failing = SecurityHeaders({
      extra: { "X-1": "v" },
    });
    // Simulate an engine failure by using a broken response object.
    const brokenRes = { setHeader: () => { throw new Error("boom"); } };
    failing.middleware()({} as never, brokenRes as never, (err) => {
      captured = err;
    });
    expect(captured).toBeInstanceOf(Error);
    expect((captured as Error).message).toBe("boom");
  });

  test("without next, errors are rethrown (raw node handler style)", () => {
    const brokenRes = { setHeader: () => { throw new Error("boom"); } };
    expect(() => SecurityHeaders().middleware()({} as never, brokenRes as never)).toThrow("boom");
  });
});

describe("headers fetch adapter", () => {
  test("decorates the handler response, preserving status and body", async () => {
    const wrapped = SecurityHeaders().fetchHandler(async () => new Response("hello", { status: 201 }));
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.status).toBe(201);
    expect(await response.text()).toBe("hello");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains");
  });

  test("secure context is derived from the request URL", async () => {
    const insecure = await SecurityHeaders().fetchHandler(() => new Response("ok"))(
      new Request("http://api.example.com/")
    );
    expect(insecure.headers.get("Strict-Transport-Security")).toBeNull();

    const secure = await SecurityHeaders().fetchHandler(() => new Response("ok"))(
      new Request("https://api.example.com/")
    );
    expect(secure.headers.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains");
  });

  test("overwrite: false keeps the handler's own headers", async () => {
    const wrapped = SecurityHeaders({ overwrite: false }).fetchHandler(
      () => new Response("ok", { headers: { "X-Frame-Options": "SAMEORIGIN" } })
    );
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.headers.get("X-Frame-Options")).toBe("SAMEORIGIN");
  });

  test("overwrite: true replaces same-named handler headers", async () => {
    const wrapped = SecurityHeaders().fetchHandler(
      () => new Response("ok", { headers: { "X-Frame-Options": "SAMEORIGIN" } })
    );
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
  });

  test("remove strips handler headers", async () => {
    const wrapped = SecurityHeaders({ remove: ["Server"] }).fetchHandler(
      () => new Response("ok", { headers: { Server: "nginx", "X-Keep": "1" } })
    );
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.headers.get("Server")).toBeNull();
    expect(response.headers.get("X-Keep")).toBe("1");
  });

  test("downstream handler errors propagate, never swallowed", async () => {
    const wrapped = SecurityHeaders().fetchHandler(async () => {
      throw new Error("handler boom");
    });
    await expect(wrapped(new Request("https://api.example.com/"))).rejects.toThrow("handler boom");
  });

  test("set-cookie headers survive the wrapper", async () => {
    const wrapped = SecurityHeaders().fetchHandler(
      () => new Response("ok", { headers: { "Set-Cookie": "session=abc; HttpOnly" } })
    );
    const response = await wrapped(new Request("https://api.example.com/"));
    expect(response.headers.get("Set-Cookie")).toBe("session=abc; HttpOnly");
  });
});

describe("headers module surface", () => {
  test("headers() returns a Web-standard Headers view", () => {
    const headers = SecurityHeaders().headers({ secure: true });
    expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headers.get("Strict-Transport-Security")).toBe("max-age=31536000; includeSubDomains");
  });

  test("all surfaces agree on the same configuration", () => {
    const module = SecurityHeaders({ xssProtection: "1; mode=block" });
    expect(module.build().headers["X-XSS-Protection"]).toBe("1; mode=block");
    expect(module.headers().get("X-XSS-Protection")).toBe("1; mode=block");
  });
});