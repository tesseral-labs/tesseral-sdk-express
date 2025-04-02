import { AccessTokenClaims } from "@tesseral/tesseral-node/api";
import crypto from "node:crypto";

export class Authenticator {
  private publishableKey: string;
  private configApiHostname: string;
  private jwksRefreshIntervalSeconds: number;
  private projectId: string;
  private jwks: Record<string, crypto.KeyObject>;
  private jwksNextRefreshUnixSeconds: number;

  constructor({
    publishableKey,
    configApiHostname,
    jwksRefreshIntervalSeconds,
  }: {
    publishableKey: string;
    configApiHostname: string;
    jwksRefreshIntervalSeconds: number;
  }) {
    this.publishableKey = publishableKey;
    this.configApiHostname = configApiHostname;
    this.jwksRefreshIntervalSeconds = jwksRefreshIntervalSeconds;
    this.projectId = "";
    this.jwks = {};
    this.jwksNextRefreshUnixSeconds = 0;
  }

  public async authenticateAccessToken(
    accessToken: string,
  ): Promise<AccessTokenClaims> {
    await this.updateConfigData();
    return authenticateAccessToken({
      jwks: this.jwks,
      accessToken,
      nowUnixSeconds: Math.floor(Date.now() / 1000),
    });
  }

  public async getProjectId(): Promise<string> {
    await this.updateConfigData();
    return this.projectId;
  }

  private async updateConfigData(): Promise<void> {
    if (this.jwksNextRefreshUnixSeconds < Date.now() / 1000) {
      const { projectId, jwks } = await fetchConfig({
        configApiHostname: this.configApiHostname,
        publishableKey: this.publishableKey,
      });

      this.projectId = projectId;
      this.jwks = jwks;
      this.jwksNextRefreshUnixSeconds =
        Date.now() / 1000 + this.jwksRefreshIntervalSeconds;
    }
  }
}

interface Config {
  projectId: string;
  jwks: Record<string, crypto.KeyObject>;
}

async function fetchConfig({
  configApiHostname,
  publishableKey,
}: {
  configApiHostname: string;
  publishableKey: string;
}): Promise<Config> {
  const response = await fetch(
    `https://${configApiHostname}/v1/config/${publishableKey}`,
  );
  if (!response.ok) {
    throw new Error("Failed to fetch JWKS");
  }
  return parseConfig(await response.json());
}

function authenticateAccessToken({
  jwks,
  accessToken,
  nowUnixSeconds,
}: {
  jwks: Record<string, crypto.KeyObject>;
  accessToken: string;
  nowUnixSeconds: number;
}): AccessTokenClaims {
  const parts = accessToken.split(".");
  if (parts.length !== 3) {
    throw new InvalidAccessTokenError();
  }

  const [rawHeader, rawClaims, rawSignature] = parts;

  const parsedHeader = JSON.parse(base64URLDecode(parts[0]));
  if (!(parsedHeader.kid in jwks)) {
    throw new InvalidAccessTokenError();
  }

  const publicKey = jwks[parsedHeader.kid];

  const signature = Buffer.from(
    rawSignature.replace(/-/g, "+").replace(/_/g, "/"),
    "base64",
  );
  const valid = crypto.verify(
    "sha256",
    Buffer.from(rawHeader + "." + rawClaims),
    {
      key: publicKey,
      dsaEncoding: "ieee-p1363",
    },
    signature,
  );
  if (!valid) {
    throw new InvalidAccessTokenError();
  }

  const claims = JSON.parse(base64URLDecode(rawClaims)) as AccessTokenClaims;
  if (nowUnixSeconds < claims.nbf! || claims.exp! < nowUnixSeconds) {
    throw new InvalidAccessTokenError();
  }

  return claims;
}

function base64URLDecode(s: string): string {
  return Buffer.from(
    s.replace(/-/g, "+").replace(/_/g, "/"),
    "base64",
  ).toString();
}

function parseConfig(configData: any): Config {
  const jwks: Record<string, crypto.KeyObject> = {};
  for (const key of configData.keys) {
    if (key.kty !== "EC" || key.crv !== "P-256") {
      throw new Error(
        "internal error: jwks must contain P-256 elliptic public keys",
      );
    }

    jwks[key.kid] = crypto.createPublicKey({
      format: "jwk",
      key,
    });
  }

  return {
    projectId: configData.projectId,
    jwks,
  };
}

class InvalidAccessTokenError extends Error {
  constructor() {
    super("Invalid access token");
    Object.setPrototypeOf(this, InvalidAccessTokenError.prototype);
  }
}
