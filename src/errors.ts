export class MissingAuthDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MissingAuthDataError";
  }
}
