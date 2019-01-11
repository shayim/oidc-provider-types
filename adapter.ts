import { Provider } from "./provider";
import { IClient } from "./client";
import { IOpaqueFormat, IJwtFormat } from "./format";
import { IOidcSession } from "./oidcSession";
import { IInteractionSession } from "./iterationSession";

export declare class Adapter {
  constructor(name: string);

  upsert(id: string, payload: object, expiresIn: number): Promise<any>;

  static connect(provider: Provider): Promise<any>;
}

export interface IAdapter {
  constructor(
    name:
      | "Session"
      | "AccessToken"
      | "AuthorizationCode"
      | "RefreshToken"
      | "ClientCredentials"
      | "Client"
      | "InitialAccessToken"
      | "RegistrationAccessToken"
      | "DeviceCode"
  );

  find(id: string): Promise<object | null>;
  findByUserCode(userCode: string): Promise<object | null>;
  upsert(
    id: string,
    payload:
      | IOpaqueFormat
      | IJwtFormat
      | IClient
      | IOidcSession
      | IInteractionSession,
    expiresIn: number
  );
  consume(id): Promise<any>;
  destroy(id): Promise<any>;
}
