import cookieParser from "cookie-parser";
import express, { NextFunction, Request, Response, Router } from "express";
import { AccessTokenAuthenticator } from "@tesseral/tesseral-node";
import { RequestAuthData } from "./context";

/**
 * Options for {@link requireAuth}.
 */
export interface Options {
  publishableKey: string;
  configApiHostname?: string;
  jwksRefreshIntervalSeconds?: number;
}

/**
 * Returns an Express middleware that requires requests be authenticated.
 *
 * Unauthenticated requests receive a 401 Unauthorized error.
 *
 * Authenticated requests carry authentication data, which you can read using
 * organizationId(), accessTokenClaims(), credentials(), or hasPermission().
 *
 * @param publishableKey Your Tesseral Publishable Key. Required.
 *
 * @param configApiHostname Optional. The hostname of the Tesseral Config API.
 * Defaults to "config.tesseral.com".
 *
 * @param jwksRefreshIntervalSeconds Optional. requireAuth maintains a cache of
 * public keys that access tokens may be signed with. This controls how often
 * that cache is updated. Defaults to 3600 seconds (1 hour).
 */
export function requireAuth({
  publishableKey,
  configApiHostname = "config.tesseral.com",
  jwksRefreshIntervalSeconds = 3600,
}: Options): Router {
  const authenticator = new AccessTokenAuthenticator({
    publishableKey,
    configApiHostname,
    jwksRefreshIntervalSeconds,
  });

  const router = express.Router();

  router.use(cookieParser());

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    const projectID = await authenticator.getProjectId();
    const accessToken = extractAccessToken(projectID, req);

    try {
      const accessTokenClaims = await authenticator.authenticateAccessToken({
        accessToken,
      });

      const auth: RequestAuthData = {
        accessToken,
        accessTokenClaims,
      };

      Object.assign(req, { auth });
      return next();
    } catch {
      res.sendStatus(401);
      return;
    }
  });

  return router;
}

const PREFIX_BEARER = "Bearer ";

function extractAccessToken(projectId: string, req: Request): string {
  if (req.headers.authorization?.startsWith(PREFIX_BEARER)) {
    return req.headers.authorization.substring(PREFIX_BEARER.length);
  }

  const cookieName = `tesseral_${projectId}_access_token`;
  if (req.cookies[cookieName]) {
    return req.cookies[cookieName];
  }
  return "";
}
