import {
  AccessTokenClaims,
  AuthenticateApiKeyResponse,
} from "@tesseral/tesseral-node/api";
import { Request } from "express";
export interface RequestAuthData {
  accessToken?: string;
  accessTokenClaims?: AccessTokenClaims;
  apiKeyDetails?: AuthenticateApiKeyResponse;
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
      `Called ${name}() on a request that does not carry auth data. Did you forget to express.use(requireAuth())?`
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
  const authData = extractAuthData("organizationId", req);

  if (authData.apiKeyDetails?.organizationId) {
    return authData.apiKeyDetails.organizationId;
  } else if (authData.accessTokenClaims) {
    return authData.accessTokenClaims.organization?.id;
  }

  throw new Error(
    `Called organizationId() on a request that does not carry auth data. Did you forget to express.use(requireAuth())?`
  );
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
  const authData = extractAuthData("accessTokenClaims", req);

  if (!authData.accessTokenClaims) {
    throw new Error(
      `Called accessTokenClaims() on a request that does not carry an accessToken. Did you forget to express.use(requireAuth())?`
    );
  }

  return authData.accessTokenClaims;
}

/**
 * Returns the request's original credentials.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function credentials(req: Request): string {
  const authData = extractAuthData("credentials", req);

  if (!authData.accessToken) {
    throw new Error(
      `Called credentials() on a request that does not carry an accessToken. Did you forget to express.use(requireAuth())?`
    );
  }

  return authData.accessToken;
}

/**
 * Returns the request's API key ID.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function apiKeyId(req: Request): string {
  const authData = extractAuthData("apiKeyId", req);

  if (!authData.apiKeyDetails?.apiKeyId) {
    throw new Error(
      `Called apiKeyId() on a request that does not carry an API key. Did you forget to express.use(requireAuth())?`
    );
  }

  return authData.apiKeyDetails.apiKeyId;
}

/**
 * Returns the request's API key actions.
 *
 * Throws if the request was not processed through requireAuth().
 *
 * @param req An Express Request object.
 */
export function actions(req: Request): string[] {
  const authData = extractAuthData("actions", req);

  if (!authData.apiKeyDetails?.actions) {
    throw new Error(
      `Called actions() on a request that does not carry an API key. Did you forget to express.use(requireAuth())?`
    );
  }

  return authData.apiKeyDetails.actions;
}
