import {
  AccessTokenClaims,
  AuthenticateApiKeyResponse,
} from "@tesseral/tesseral-node/api";
import { NotAnAccessTokenError } from "./errors";
import { Request } from "express";

export enum AuthType {
  ACCESS_TOKEN = "accessToken",
  API_KEY = "apiKey",
  NONE = "none",
}

export interface APIKeyDetails extends AuthenticateApiKeyResponse {
  apiKeySecretToken: string;
}

export interface AccessTokenDetails {
  accessToken?: string;
  accessTokenClaims?: AccessTokenClaims;
}

export interface RequestAuthData {
  accessToken?: AccessTokenDetails;
  apiKey?: APIKeyDetails;
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
  } else if (authData.apiKey) {
    return AuthType.API_KEY;
  }

  // We shoudl never reach this point, because the request should always
  // have either an access token or API key details.
  throw new Error("Unreachable");
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

  if (authData.apiKey?.organizationId) {
    return authData.apiKey.organizationId;
  } else if (authData.accessToken?.accessTokenClaims) {
    return authData.accessToken?.accessTokenClaims.organization?.id;
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

  if (!authData.accessToken?.accessTokenClaims) {
    throw new NotAnAccessTokenError(
      `Called accessTokenClaims() on a request that carries an API key, not an access token.`
    );
  }

  return authData.accessToken?.accessTokenClaims;
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

  if (authData.apiKey?.apiKeySecretToken) {
    return authData.apiKey.apiKeySecretToken;
  } else if (authData.accessToken?.accessToken) {
    return authData.accessToken?.accessToken;
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
  const authData = extractAuthData("hasPermission", req);

  if (authData?.accessToken?.accessTokenClaims?.actions) {
    return authData.accessToken.accessTokenClaims.actions.includes(action);
  } else if (authData?.apiKey?.actions) {
    return authData.apiKey.actions.includes(action);
  }

  // We should never reach this point, because the request should always
  // have either an access token or API key details.
  throw new Error(`Unreachable`);
}
