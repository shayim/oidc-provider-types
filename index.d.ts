import { EventEmitter } from "events";
import { IncomingMessage, ServerResponse } from "http";
import { Http2ServerRequest, Http2ServerResponse } from "http2";
import { Server } from "http";

import * as Koa from "koa";

import { AccessToken } from "./accessToken";
import { AuthorizationCode } from "./authorizationCode";
import { DeviceCode } from "./deviceCode";
import { IAdapter } from "./adapter";
import { BaseToken } from "./baseToken";
import { InitialAccessToken } from "./initialAccessToken";

import { OIDCContext } from "./OIDCContext";
import { IConfiguration } from "./configuration";

interface IProvider {}

declare class Provider extends EventEmitter {
  static useGot(): void;
  static useRequest(): void;

  // properties
  env: string;
  proxy: boolean;
  subdomainOffset: number;
  keys: string[];

  // getters
  readonly callback: (
    req: IncomingMessage | Http2ServerRequest,
    res: ServerResponse | Http2ServerResponse
  ) => void;

  readonly app: any;

  // getters && setters
  defaultHttpOptions: any;

  constructor(issuer: string, setup: IConfiguration);

  intialize(setup: {
    adapter?: IAdapter;
    clients?: Provider.ClientMetadata[];
    keystore?: any;
  }): Promise<Provider>;

  // methods
  use(fn: Koa.Middleware): void;
  listen(...arg): Server;
  httpOptions(values): any;
  registerGrantType(
    name: string,
    handlerFactory: Function,
    params: Set<string>,
    dupes: string | Array<string> | Set<string>
  ): void;
  registerResponseMode(name: string, handler: Function): void;
  pathFor(name: string, opts: any): string;
  url(name: string, opts: any);
  cookieName(type: string): string;

  // @api public
  interactionDetails(
    req: IncomingMessage | Http2ServerRequest
  ): Promise<Provider.InteractionSession>;

  // @api public
  interactionFinished(
    req: IncomingMessage | Http2ServerRequest,
    res: ServerResponse | Http2ServerResponse,
    result: Provider.InteractionResult
  ): Promise<void>;

  // @api public
  interactionResult(
    req: IncomingMessage | Http2ServerRequest,
    res: ServerResponse | Http2ServerResponse,
    result: Provider.InteractionResult
  ): Promise<string>;

  // @api public
  setProviderSession(
    req: IncomingMessage | Http2ServerRequest,
    res: ServerResponse | Http2ServerResponse,
    payload: {
      account: string;
      ts: number;
      remember: boolean;
      clients: Provider.IClient[];
      meta: {};
    }
  ): Promise<Session>;
}

declare namespace Provider {
  interface InteractionSession {
    accountId: string;
    exp: number;
    signed: [];

    uuid: string;
    params: { client_id };
    interaction: { error?; reason?; description? };
    returnTo: string;
    result?: InteractionResult;
  }

  interface InteractionResult {
    login: {
      account: string; // logged-in account id
      acr: string; // acr value for the authentication
      remember: boolean; // true if provider should use a persistent cookie rather than a session one
      ts: number; // unix timestamp of the authentication
    };
    consent: {
      rejectedScopes: string[]; // array of strings, scope names the end-user has not granted
      rejectedClaims: string[]; // array of strings, claim names the end-user has not granted
    };
    meta: {};
  }

  interface ClientMetadata {
    // RECOGNIZED_METADATA
    application_type?: "web" | "native";
    // client_id_issued_at: number; // FORBIDDEN
    client_id?: string;
    client_name?: string;
    // client_secret_expires_at; // FORBIDDEN
    client_secret: string;
    client_uri?: string;
    contacts: string[];
    default_acr_values?: string[];
    default_max_age?: number;
    grant_types?: (
      | "authorization_code"
      | "client_credentials"
      | "implicit"
      | "refresh_token"
      | "urn:ietf:params:oauth:grant-type:device_code")[];
    id_token_signed_response_alg?: string;
    initiate_login_uri?: string;
    jwks_uri?: string;
    jwks;
    logo_uri?: string;
    policy_uri?: string;
    redirect_uris: string[]; // REQUIRED
    require_auth_time?: boolean;
    response_types?: ("code" | "token" | "id_token")[];
    sector_identifier_uri?: string;
    subject_type?: "public" | "pairwise";
    token_endpoint_auth_method?:
      | "client_secret_post"
      | "client_secret_basic"
      | "client_secret_jwt"
      | "private_key_jwt"
      | "none";
    tos_uri?: string;
    userinfo_signed_response_alg?: string;
    token_endpoint_auth_signing_alg?: string;

    tls_client_auth_subject_dn?: string; // (token|revocation|introspection)EndpointAuthMethods includes 'tls_client_auth'
    introspection_endpoint_auth_method?: string; // features.introspection
    introspection_endpoint_auth_signing_alg?;

    backchannel_logout_uri: string;
    backchannel_logout_session_required?: boolean;

    id_token_encrypted_response_alg?: string;
    id_token_encrypted_response_enc?: string;
    request_object_encryption_alg?: string;
    request_object_encryption_enc?: string;
    request_object_signing_alg?: string;
    request_uris: string[];
    tls_client_certificate_bound_access_tokens: boolean;

    userinfo_encrypted_response_alg?: string;
    userinfo_encrypted_response_enc?: string;

    // TO FIND OUT
    introspectionSignedResponseAlg?;
    introspectionEncryptedResponseAlg?;
    introspectionEncryptedResponseEnc?;

    authorizationSignedResponseAlg?;
    authorizationEncryptedResponseAlg?;
    authorizationEncryptedResponseEnc?;

    keystore?; // !!! keystore.refresh() !!! keystore.get({alg, use})
  }
}
export = Provider;
