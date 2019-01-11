import { IClient } from "./client";

export declare class IdToken {
  available: {};
  extra: {};
  client: IClient;

  constructor(available: {}, client: IClient);
  static expiresIn(...args): number | undefined;
  static validate(jwt, client: IClient);

  // methods
  set(key, value): void; // set extra
}
