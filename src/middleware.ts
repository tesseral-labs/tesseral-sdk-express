import cookieParser from "cookie-parser";
import express, { NextFunction, Request, Response, Router } from "express";
import { AccessTokenAuthenticator } from "@tesseral/tesseral-node";
import { RequestAuthData } from "./context";
import { AuthenticateApiKeyResponse } from "@tesseral/tesseral-node/api";

/**
 * Options for {@link requireAuth}.
 */
export interface Options {
  publishableKey: string;
  configApiHostname?: string;
  jwksRefreshIntervalSeconds?: number;
  withAPIKeys?: boolean;
  backendApiKey?: string;
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
  withAPIKeys = false,
  backendApiKey,
}: Options): Router {
  if (withAPIKeys && !backendApiKey) {
    throw new Error("`withAPIKeys` requires a `backendApiKey`.");
  }

  const accessTokenAuthenticator = new AccessTokenAuthenticator({
    publishableKey,
    configApiHostname,
    jwksRefreshIntervalSeconds,
  });

  const router = express.Router();

  router.use(cookieParser());

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    const projectID = await accessTokenAuthenticator.getProjectId();
    const accessToken = extractAccessToken(projectID, req);

    if (
      /^[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.test(accessToken)
    ) {
      // accessToken is a JWT
      try {
        const accessTokenClaims =
          await accessTokenAuthenticator.authenticateAccessToken({
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
    } else if (/[a-z0-9_]+/.test(accessToken) && withAPIKeys && backendApiKey) {
      // accessToken is presumably an API key
      try {
        const apiKeyDetails = await authenticateApiKey(
          backendApiKey,
          accessToken
        );

        const auth: RequestAuthData = {
          apiKeyDetails: {
            ...apiKeyDetails,
            apiKeySecretToken: accessToken,
          },
        };
        Object.assign(req, { auth });
        return next();
      } catch (e) {
        res.sendStatus(401);
        return;
      }
    } else {
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

async function authenticateApiKey(
  backendApiKey: string,
  apiKey: string
): Promise<AuthenticateApiKeyResponse> {
  const response = await fetch(
    "https://api.tesseral.com/v1/api-keys/validate",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${backendApiKey}`,
      },
      body: JSON.stringify({ secretToken: apiKey }),
    }
  );

  if (!response.ok) {
    throw new Error(`Failed to validate API key: ${response.statusText}`);
  }

  return (await response.json()) as AuthenticateApiKeyResponse;
}
