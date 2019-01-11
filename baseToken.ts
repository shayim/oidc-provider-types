import { IAdapter } from "./adapter";
import { IClient } from "./client";

export declare class BaseToken {
  jti: string;
  kind: string; // this.constructor.name
  clientId: string;

  constructor(jti: string, kind: string, payload: {});

  // set
  client: IClient;

  // get
  readonly isValid: boolean;
  readonly isExpired: boolean;
  readonly remainingTTL: number;
  readonly expiration: number;
  readonly adapter: IAdapter;

  // method
  save(): Promise<string>; // return token id
  static find(token: string, opts: {}): Promise<any | undefined>; // return AuthorizationCode | AccessToken ...
  destroy();

  static expiresIn(...args): number | undefined;
  static readonly IN_PAYLOAD: string[];
  static readonly adapter: IAdapter;

  // prototype
  getValueAndPayload(): []; //  [value, payload]
  getTokenId(token): string;

  static generateTokenId(): string;
  static verify(token, stored, {}): {};

  name: string;
  exp: number;
}
