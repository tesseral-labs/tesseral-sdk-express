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

/**
 * The ID of the organization the requester belongs to.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function organizationId(req: Request): string {
  return extractAuthData("organizationId", req).accessTokenClaims.organization!
    .id!;
}

/**
 * Returns the claims inside the request's access token, if any.
 *
 * Future versions of this package may add support for other kinds of
 * authentication than access tokens, in which case this function may throw an
 * Error.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function accessTokenClaims(req: Request): AccessTokenClaims {
  return extractAuthData("accessTokenClaims", req).accessTokenClaims;
}

/**
 * Returns the request's original credentials.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function credentials(req: Request): string {
  return extractAuthData("credentials", req).accessToken;
}

/**
 * Returns true if the requester has permission to carry out the given action.
 * Returns false otherwise.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 * @param action An action name, such as "acme.widgets.edit".
 */
export function hasPermission(req: Request, action: string): boolean {
  const claims = extractAuthData("hasPermission", req).accessTokenClaims;
  if (!claims.actions) {
    return false;
  }

  return claims.actions.includes(action);
}
