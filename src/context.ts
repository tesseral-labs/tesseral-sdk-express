import {
  AccessTokenClaims,
  AuthenticateApiKeyResponse,
} from "@tesseral/tesseral-node/api";
import {
  NoAuthDataError,
  NotAnAccessTokenError,
  UnreachableError,
} from "./errors";
import { Request } from "express";

export enum AuthType {
  ACCESS_TOKEN = "accessToken",
  API_KEY = "apiKey",
  NONE = "none",
}

export interface APIKeyDetails extends AuthenticateApiKeyResponse {
  apiKeySecretToken: string;
}

export interface RequestAuthData {
  accessToken?: string;
  accessTokenClaims?: AccessTokenClaims;
  apiKeyDetails?: APIKeyDetails;
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
 * The type of authentication used in the request.
 *
 * This is either "accessToken", "apiKey", or "none".
 *
 * @param req An Express Request object.
 */

export function authType(req: Request): AuthType {
  const authData = extractAuthData("authType", req);
  if (authData.accessToken) {
    return AuthType.ACCESS_TOKEN;
  } else if (authData.apiKeyDetails) {
    return AuthType.API_KEY;
  }

  return AuthType.NONE;
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

  // We should never reach this point, because the request should always
  // have either an access token or API key details.
  throw new Error(`Unreachable`);
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
    if (authData.apiKeyDetails) {
      throw new NotAnAccessTokenError(
        `Called accessTokenClaims() on a request that carries an API key, not an access token.`
      );
    }

    // We should never reach this point, because the request should always
    // have either an access token or API key details.
    throw new Error(`Unreachable`);
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

  if (authData.apiKeyDetails?.apiKeySecretToken) {
    return authData.apiKeyDetails.apiKeySecretToken;
  } else if (authData.accessToken) {
    return authData.accessToken;
  }

  // We should never reach this point, because the request should always
  // have either an access token or API key details.
  throw new Error(`Unreachable`);
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
  const actions = extractAuthData("hasPermission", req).apiKeyDetails?.actions;

  if (claims?.actions) {
    return claims.actions.includes(action);
  } else if (actions) {
    return actions.includes(action);
  }

  return false;
}
