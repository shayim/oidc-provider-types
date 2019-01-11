import { EventEmitter } from "events";
import { Server } from "http";

import * as Koa from "koa";

import { IAdapter } from "./adapter";
import { BaseToken } from "./baseToken";
import { IClient } from "./client";
import { Claims } from "./claims";
import { IInteractionResult } from "./format";

import { OIDCContext } from "./OIDCContext";
import {
  IConfiguration,
  AccessToken,
  AuthorizationCode,
  DeviceCode,
  InitialAccessToken
} from "./configuration";

export interface IProvider {
  defaultHttpOptions: { timeout?: number; headers?: {} };
}

export declare class Provider extends EventEmitter {
  constructor(issuer: string, setup: IConfiguration);

  intialize(setup: {
    adapter?: IAdapter;
    clients?: IClient[];
    keystore?;
  }): Promise<void>;
  interactionDetails(req);
  interactionFinished(req, res, result: IInteractionResult);
  interactionResult(req, res, result);
  pathFor(name: string, mountPath: string, opts: {}): string;
  setProviderSession(
    req,
    res,
    payload: {
      account: string;
      ts: number;
      remember: boolean;
      clients: IClient[];
      meta;
    }
  );
  registerGrantType(name, handlerFactory, params, dupes): void;
  static useGot(): void;
  static useRequest(): void;

  // getter && setter
  defaultHttpOptions;
  readonly AccessToken: AccessToken;
  readonly AuthorizationCode: AuthorizationCode;
  readonly app; // Koa Application
  readonly BaseToken: BaseToken;
  readonly callback; // Koa Application callback
  readonly Claims: Claims;

  readonly DeviceCode: DeviceCode;
  readonly InitialAccessToken: InitialAccessToken;
  readonly OIDCContext: OIDCContext;

  // method
  cookieName(type): string; // return configuration cookie.names.${type}
  listen(...arg): Server;
  use(fn: Koa.Middleware): void;
}
