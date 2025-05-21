export class NotAnAccessTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotAnAccessTokenError";
  }
}

export class NoAccessTokenClaimsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoAccessTokenClaimsError";
  }
}

export class NoAuthDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoAuthDataError";
  }
}

export class UnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnreachableError";
  }
}
