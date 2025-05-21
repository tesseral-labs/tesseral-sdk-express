export class NotAnAccessTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotAnAccessTokenError";
  }
}
