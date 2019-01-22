export declare class Client {
  noManage: boolean;

  static cacheClear(id?: string): void;
  static find(id, opts: { freash: boolean }): Promise<Client>;

  // methods

  /// create a logoutToken: new IdToken({sub}, this)
  /// logoutToken.mask = {sub:null}
  /// logoutToken.set(jti, uuid())
  /// logoutToken.set('sid', sid)
  /// logoutToken.sign({noExp: true})
  /// http Post this.backchannelLogoutUri with logoutToken
  backchannelLogout(sub: string, sid: string): Promise<any>;

  /// check this.responseTypes includes type
  responseTypeAllowed(type): boolean;

  /// check this.grantTypes include type
  grantTypeAllowed(type): boolean;

  /// check this.redirectUris include redirectUri
  redirectUriAllowed(redirectUri): boolean;

  /// store the origins of this.redirectUris into the Set of instance(this).redirectUriOrigins
  /// check instance(this).redirectUriOrigins has origin
  originAllowed(origin): boolean;

  /// check this.webMessageUris includes webMessageUri
  webMessageUriAllowed(webMessageUri): boolean;

  /// check this.requestUris includes uri
  requestUriAllowed(uri): boolean;

  /// check this.postLogoutRedirectUris includes uri
  postLogoutRedirectUriAllowed(uri): boolean;

  /// return this with snakeCased key
  metadata(): IClient;

  // method getters
  readonly sectorIdentifier;
}
