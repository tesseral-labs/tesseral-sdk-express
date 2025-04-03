import { accessTokenClaims, credentials, organizationId } from "../src";

describe("context", () => {
  it("reads out credentials", () => {
    const req = { auth: { accessToken: "abc" } }
    expect(credentials(req as any)).toEqual("abc")
  })

  it("reads out accessTokenClaims", () => {
    const req = { auth: { accessTokenClaims: { organization: { id: "123" } } } }
    expect(accessTokenClaims(req as any)).toEqual({ organization: { id: "123" } })
  })

  it("reads out organizationId", () => {
    const req = { auth: { accessTokenClaims: { organization: { id: "123" } } } }
    expect(organizationId(req as any)).toEqual("123")
  })
})
