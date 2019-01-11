export interface IOidcSession {
  account: string;
  authorizations: { sid };
  loginTs: number;
  exp: number;
}
