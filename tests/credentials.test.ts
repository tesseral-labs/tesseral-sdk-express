import { isJWTFormat, isAPIKeyFormat } from "../src/credentials";

describe("credentials", () => {
  describe("isJWTFormat", () => {
    it("returns true for a valid JWT format", () => {
      const validJWT =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6" +
        "IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      expect(isJWTFormat(validJWT)).toBe(true);
    });

    it("returns false if JWT is missing a part", () => {
      expect(isJWTFormat("header.payload")).toBe(false);
    });

    it("returns false if parts contain invalid characters", () => {
      const invalidJWT = "header.payload.with=illegal&chars";
      expect(isJWTFormat(invalidJWT)).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(isJWTFormat("")).toBe(false);
    });

    it("returns false for extra segments", () => {
      const extraSegment = "a.b.c.d";
      expect(isJWTFormat(extraSegment)).toBe(false);
    });
  });

  describe("isAPIKeyFormat", () => {
    it("returns true for valid API key format", () => {
      expect(isAPIKeyFormat("abc123_underscore")).toBe(true);
    });

    it("returns false for uppercase letters", () => {
      expect(isAPIKeyFormat("ABC123")).toBe(false);
    });

    it("returns false for invalid characters", () => {
      expect(isAPIKeyFormat("key-with-dash")).toBe(false);
    });

    it("returns false for spaces", () => {
      expect(isAPIKeyFormat("key with space")).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(isAPIKeyFormat("")).toBe(false);
    });
  });
});
