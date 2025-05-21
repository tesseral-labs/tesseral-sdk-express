import { accessTokenClaims, credentials, organizationId } from "../src";
import { authType, hasPermission } from "../src/context";

describe("context", () => {
  it("reads out credentials from accessToken", () => {
    const req = { auth: { accessToken: { accessToken: "abc" } } };
    expect(credentials(req as any)).toEqual("abc");
  });

  it("reads out credentials from apiKeyDetails", () => {
    const req = {
      auth: { apiKey: { apiKeySecretToken: "xyz" } },
    };
    expect(credentials(req as any)).toEqual("xyz");
  });

  it("reads out accessTokenClaims", () => {
    const req = {
      auth: {
        accessToken: { accessTokenClaims: { organization: { id: "123" } } },
      },
    };
    expect(accessTokenClaims(req as any)).toEqual({
      organization: { id: "123" },
    });
  });

  it("reads out organizationId for accessToken", () => {
    const req = {
      auth: {
        accessToken: { accessTokenClaims: { organization: { id: "123" } } },
      },
    };
    expect(organizationId(req as any)).toEqual("123");
  });

  it("reads out organizationId for apiKeyDetails", () => {
    const req = {
      auth: {
        apiKey: { organizationId: "456", actions: ["a.b.c"] },
      },
    };
    expect(organizationId(req as any)).toEqual("456");
  });

  it("reads out authType for accessToken", () => {
    const req = {
      auth: { accessToken: { accessToken: "abc.efg.hij" } },
    };
    expect(authType(req as any)).toEqual("access_token");
  });

  it("reads out authType for apiKeyDetails", () => {
    const req = {
      auth: {
        apiKey: { organizationId: "456", actions: ["a.b.c"] },
      },
    };
    expect(authType(req as any)).toEqual("api_key");
  });

  describe("hasPermission", () => {
    it("returns true if and only if action is present for accessTokenClaims", () => {
      const req = {
        auth: {
          accessToken: { accessTokenClaims: { actions: ["a.b.c", "d.e.f"] } },
        },
      };
      expect(hasPermission(req as any, "a.b.c")).toBe(true);
      expect(hasPermission(req as any, "d.e.f")).toBe(true);
      expect(hasPermission(req as any, "x.y.z")).toBe(false);
    });

    it("returns true if and only if action is present for apiKeyDetails", () => {
      const req = {
        auth: {
          apiKey: {
            actions: ["a.b.c", "d.e.f"],
            organizationId: "123",
          },
        },
      };
      expect(hasPermission(req as any, "a.b.c")).toBe(true);
      expect(hasPermission(req as any, "d.e.f")).toBe(true);
      expect(hasPermission(req as any, "x.y.z")).toBe(false);
    });

    it("returns false if there is no actions claim at all", () => {
      const req = {
        auth: { accessToken: { accessTokenClaims: {} } },
      };
      expect(hasPermission(req as any, "a.b.c")).toBe(false);
    });
  });
});
