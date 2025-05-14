import { accessTokenClaims, credentials, organizationId } from "../src";
import { hasPermission } from "../src/context";

describe("context", () => {
  it("reads out credentials", () => {
    const req = { auth: { accessToken: "abc" } };
    expect(credentials(req as any)).toEqual("abc");
  });

  it("reads out accessTokenClaims", () => {
    const req = {
      auth: { accessTokenClaims: { organization: { id: "123" } } },
    };
    expect(accessTokenClaims(req as any)).toEqual({
      organization: { id: "123" },
    });
  });

  it("reads out organizationId", () => {
    const req = {
      auth: { accessTokenClaims: { organization: { id: "123" } } },
    };
    expect(organizationId(req as any)).toEqual("123");
  });

  describe("hasPermission", () => {
    it("returns true if and only if action is present", () => {
      const req = {
        auth: { accessTokenClaims: { actions: ["a.b.c", "d.e.f"] } },
      };
      expect(hasPermission(req as any, "a.b.c")).toBe(true);
      expect(hasPermission(req as any, "d.e.f")).toBe(true);
      expect(hasPermission(req as any, "x.y.z")).toBe(false);
    });

    it("returns false if there is no actions claim at all", () => {
      const req = {
        auth: { accessTokenClaims: {} },
      };
      expect(hasPermission(req as any, "a.b.c")).toBe(false);
    });
  });
});
