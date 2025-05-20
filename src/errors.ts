export class NoAuthDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoAuthDataError";
  }
}

export class NoAccessTokenClaimsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoAccessTokenClaimsError";
  }
}

export class NoCredentialsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoCredentialsError";
  }
}
