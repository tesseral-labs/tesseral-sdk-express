import cookieParser from "cookie-parser";
import express, { NextFunction, Request, Response, Router } from "express";
import {
  AccessTokenAuthenticator,
  InvalidAccessTokenError,
  TesseralClient,
} from "@tesseral/tesseral-node";
import { RequestAuthData } from "./context";
import { isAPIKeyFormat, isJWTFormat } from "./credentials";
import { BadRequestError } from "@tesseral/tesseral-node/api";

/**
 * Options for {@link requireAuth}.
 */
export interface Options {
  publishableKey: string;
  configApiHostname?: string;
  jwksRefreshIntervalSeconds?: number;
  apiKeysEnabled?: boolean;
  tesseralClient?: TesseralClient;
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
  apiKeysEnabled = false,
  tesseralClient,
}: Options): Router {
  // If apiKeysEnabled is true, tesseralClient must be provided or
  // TESSERAL_BACKEND_API_KEY must be set in the environment.
  //
  // If tesseralClient is provided, it must be able to use the backend API,
  // otherwise API Key authentication will fail.
  if (
    apiKeysEnabled &&
    !tesseralClient &&
    !process.env.TESSERAL_BACKEND_API_KEY
  ) {
    throw new Error(
      "If you set apiKeysEnabled to true, then you must either provide a tesseralClient or you must set a TESSERAL_BACKEND_API_KEY environment variable."
    );
  }

  let client = tesseralClient || new TesseralClient();

  const accessTokenAuthenticator = new AccessTokenAuthenticator({
    publishableKey,
    configApiHostname,
    jwksRefreshIntervalSeconds,
  });

  const router = express.Router();

  router.use(cookieParser());

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    const projectID = await accessTokenAuthenticator.getProjectId();
    const credential = extractCredential(projectID, req);

    if (isJWTFormat(credential)) {
      // accessToken is a JWT
      try {
        const accessTokenClaims =
          await accessTokenAuthenticator.authenticateAccessToken({
            accessToken: credential,
          });
        const auth: RequestAuthData = {
          accessToken: {
            accessToken: credential,
            accessTokenClaims,
          },
        };

        Object.assign(req, { auth });
      } catch (e) {
        if (e instanceof InvalidAccessTokenError) {
          res.sendStatus(401);
          return;
        }

        throw e;
      }

      return next();
    } else if (isAPIKeyFormat(credential) && apiKeysEnabled) {
      // accessToken is presumably an API key
      try {
        const apiKeyDetails = await client.apiKeys.authenticateApiKey({
          secretToken: credential,
        });
        const auth: RequestAuthData = {
          apiKey: {
            ...apiKeyDetails,
            apiKeySecretToken: credential,
          },
        };
        Object.assign(req, { auth });
      } catch (e) {
        if (
          e instanceof BadRequestError &&
          e.message === "unauthenticated_api_key"
        ) {
          res.sendStatus(401);
          return;
        }

        throw e;
      }
      return next();
    } else {
      res.sendStatus(401);
      return;
    }
  });

  return router;
}

const PREFIX_BEARER = "Bearer ";

function extractCredential(projectId: string, req: Request): string {
  if (req.headers.authorization?.startsWith(PREFIX_BEARER)) {
    return req.headers.authorization.substring(PREFIX_BEARER.length);
  }

  const cookieName = `tesseral_${projectId}_access_token`;
  if (req.cookies[cookieName]) {
    return req.cookies[cookieName];
  }
  return "";
}
