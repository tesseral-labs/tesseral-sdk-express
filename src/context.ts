import {
  AccessTokenClaims,
  AuthenticateApiKeyResponse,
} from "@tesseral/tesseral-node/api";
import {
  NoAccessTokenClaimsError,
  NoAuthDataError,
  NoCredentialsError,
} from "./errors";
import { Request } from "express";

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

  throw new NoAuthDataError(
    `Called organizationId() on a request that does not carry auth data.`
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
    throw new NoAccessTokenClaimsError(
      `Called accessTokenClaims() on a request that does not carry an accessToken.`
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

  if (authData.apiKeyDetails?.apiKeySecretToken) {
    return authData.apiKeyDetails.apiKeySecretToken;
  } else if (authData.accessToken) {
    return authData.accessToken;
  }

  throw new NoCredentialsError(
    `Called credentials() on a request that does not carry a valid credential.`
  );
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
