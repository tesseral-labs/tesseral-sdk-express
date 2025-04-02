import { AccessTokenClaims } from "@tesseral/tesseral-node/api";
import { Request } from "express";

export interface RequestAuthData {
  accessToken: string;
  accessTokenClaims: AccessTokenClaims;
}

interface RequestWithAuthData extends Request {
  auth: RequestAuthData;
}

function hasAuthData(req: Request): req is RequestWithAuthData {
  return "auth" in req;
}

function extractAuthData(name: string, req: Request): RequestAuthData {
  if (!hasAuthData(req)) {
    throw new Error(
      `Called ${name}() on a request that does not carry auth data. Did you forget to express.use(requireAuth())?`,
    );
  }
  return req.auth;
}

export function organizationId(req: Request): string {
  return extractAuthData("organizationId", req).accessTokenClaims.organization!
    .id!;
}

export function accessTokenClaims(req: Request): AccessTokenClaims {
  return extractAuthData("accessTokenClaims", req).accessTokenClaims;
}

export function credentials(req: Request): string {
  return extractAuthData("credentials", req).accessToken;
}
