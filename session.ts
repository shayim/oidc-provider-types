declare class Session {
  id: string;
  new: boolean;
  account: string;
  loginTs: number;

  oldId: string;
  touched: boolean;
  destroyed: boolean;

  accountId(): string; // this.account
  authTime(): number; // this.loginTs
  past(age): boolean;
  save(ttl?: number): Promise<void>;
  destroy(): Promise<void>;
  resetIdentifier(): Promise<void>;

  stateFor(clientId: string): string;
  sidFor(clientId: string, value?: string /* sid */): string | undefined; // get or set authorization.sid
  metaFor(clientId: string, value?: object /* meta */): object | undefined; // get or set authorization.meta
  promptedScopesFor(
    clientId,
    scopes?: Array<any> | Set<any>
  ): Set<any> | undefined; // get or set authorization.promptedScopes
  rejectedScopesFor(clientId, scopes?: Array<any> | Set<any>);
  promptedClaimsFor(clientId, claims?);

  static find(id): Promise<Session>;
  static get(ctx): Promise<Session>;

  // To find out
  authorizations; // { clientId: { sid, meta, promptedScopes, rejectedScopes, promptedClaims}}
}
