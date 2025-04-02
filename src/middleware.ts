import * as crypto from "node:crypto";
import { AccessTokenClaims } from "@tesseral/tesseral-node/api";
import cookieParser from "cookie-parser";
import express, { NextFunction, Request, Response, Router } from "express";

import { Authenticator } from "./authenticator";
import { RequestAuthData } from "./context";

export interface Options {
  publishableKey: string;
  configApiHostname?: string;
  jwksRefreshIntervalSeconds?: number;
}

export function requireAuth({
  publishableKey,
  configApiHostname = "config.tesseral.com",
  jwksRefreshIntervalSeconds = 3600,
}: Options): Router {
  const authenticator = new Authenticator({
    publishableKey,
    configApiHostname,
    jwksRefreshIntervalSeconds,
  });

  const router = express.Router();

  router.use(cookieParser());

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = extractAccessToken(
      await authenticator.getProjectId(),
      req,
    );
    try {
      const accessTokenClaims =
        await authenticator.authenticateAccessToken(accessToken);

      const auth: RequestAuthData = {
        accessToken,
        accessTokenClaims,
      };

      Object.assign(req, { auth });
      return next();
    } catch {
      res.status(401);
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
