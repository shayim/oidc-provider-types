import { EventEmitter } from "events";
import { IncomingMessage, ServerResponse } from "http";
import { Http2ServerRequest, Http2ServerResponse } from "http2";
import { Server } from "http";

import * as Koa from "koa";


interface IAdapter {
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

  // Conditional RECOGNIZED_METADATA

  // configuration.(token|revocation|introspection)EndpointAuthMethods includes 'tls_client_auth'
  tls_client_auth_subject_dn?: string;

  // configuration.tokenEndpointAuthSigningAlgValues // ALWAYS TRUE
  token_endpoint_auth_signing_alg?: string;

  // features.introspection
  introspection_endpoint_auth_method?: string;

  // features.introspection
  // && configuration.introspectionEndpointAuthSigningAlgValues // ALWAYS TRUE
  introspection_endpoint_auth_signing_alg?: string;

  // features.introspection
  // && configuration.features.jwtIntrospection
  introspection_signed_response_alg?: string;

  // features.introspection
  // && features.jwtIntrospection
  // && features.encryption
  introspection_encrypted_response_alg?: string;
  introspection_encrypted_response_enc?: string;

  // features.revocation
  revocation_endpoint_auth_method?: string;

  // features.revocation
  // && configuration.revocationEndpointAuthSigningAlgValues // ALWAYS TRUE
  revocation_endpoint_auth_signing_alg?: string;

  // features.sessionManagement || features.backchannelLogout || features.frontchannelLogout
  post_logout_redirect_uris?: string;

  // features.backchannelLogout
  backchannel_logout_uri?: string;
  backchannel_logout_session_required?: boolean;

  // features.frontchannelLogout
  frontchannel_logout_uri?: string;
  frontchannel_logout_session_required?: string;

  // features.request || features.requestUri
  request_object_signing_alg?: string;

  // features.request || features.requestUri
  // && features.encryption
  request_object_encryption_alg?: string;
  request_object_encryption_enc?: string;

  // features.requestUri
  request_uris?: string[];

  // features.encryption
  id_token_encrypted_response_alg?: string;
  id_token_encrypted_response_enc?: string;
  userinfo_encrypted_response_alg?: string;
  userinfo_encrypted_response_enc?: string;

  // features.jwtResponseModes
  authorization_signed_response_alg?: string;

  // features.jwtResponseModes
  // && features.encryption
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;

  // features.webMessageResponseMode
  web_message_uris?: string[];

  // features.certificateBoundAccessTokens
  tls_client_certificate_bound_access_tokens?: boolean;
}

interface IConfiguration {

  /*
   * @ mustChange
   * pairwiseIdentifier
   *
   * description: Function used by the OP when resolving pairwise ID Token and Userinfo sub claim
   *   values. See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1)
   * affects: pairwise ID Token and Userinfo sub claim values
   * recommendation: Since this might be called several times in one request with the same arguments
   *   consider using memoization or otherwise caching the result based on account and client
   *   ids.
   * default implementation
   * {
   *   return crypto
        .createHash('sha256')
        .update(client.sectorIdentifier)
        .update(accountId)
        .update(os.hostname()) // put your own unique salt here, or implement other mechanism
        .digest('hex');
   * }
   */
  pairwiseIdentifier?(accountId:string, client: Provider.Client): Promise<string>

   /*
   * @ mustChange
   * uniqueness
   *
   * description: Function resolving whether a given value with expiration is presented first time
   * affects: client_secret_jwt and private_key_jwt client authentications
   * recommendation: configure this option to use a shared store if client_secret_jwt and
   *   private_key_jwt are used
   *
   * default implementation
   * {
      if (cache.get(jti)) return false;
      cache.set(jti, true, (expiresAt - epochTime()) * 1000);
      return true;
  }
   */
  uniqueness(ctx: any, jti:string, expiresAt:number): Promise<boolean>


  findById(ctx, sub, token)

  acrValues?: string[];
  audiences(ctx, sub, token, use): Promise<string[]>;
  claims?: { [key: string]: string[] | { [key: string]: null } }; // { amr?; address?; email?; phone?; profile? }
  clientCacheDuration?: number;
  clockTolerance?: number;
  cookies?: {
    names?: {
      session?: string;
      interaction?: string;
      resume?: string;
      state?: string;
    };
    long?: {
      secure?: boolean;
      signed?: boolean;
      httpOnly?: boolean;
      maxAge?: number;
    };
    short?: {
      secure?: boolean;
      signed?: boolean;
      httpOnly?: boolean;
      maxAge?: number;
    };
    keys?: string[];
  };
  discovery?: {
    acr_values_supported?: string[] | number[];
    claim_types_supported?: ("normal" | "aggregated" | "distributed")[];
    claims_locales_supported?;
    display_values_supported?;
    op_policy_uri?;
    op_tos_uri?;
    service_documentation?;
    ui_locales_supported?;
  };
  dynamicScopes?: string[];
  extraParams?: string[] | Set<string>;
  features?: IConfigurationFeatures;
  findById?: (
    ctx,
    sub: string,
    token
  ) => {
    accountId: string;
    claims: (
      use: "id_token" | "userinfo",
      scope: string,
      claims: object,
      rejected: string[]
    ) => { sub };
  };
  formats?: {
    default?: "opaque" | "legacy";
    AccessToken?: "opaque" | "jwt" | Function;
    AuthorizationCode?: "opaque" | "jwt" | Function;
    Client?: "opaque" | "jwt" | Function;
    ClientCredentials?: "opaque" | "jwt" | Function;
    DeviceCode?: "opaque" | "jwt" | Function;
    InitialAccessToken?: "opaque" | "jwt" | Function;
    RefreshToken?: "opaque" | "jwt" | Function;
    Session?: "opaque" | "jwt" | Function;
  };
  interactionUrl?(ctx, interaction): string;
  prompts?: ("consent" | "login" | "none")[];
  routes?: {
    authorization?;
    certificates?;
    check_session?;
    code_verification?;
    device_authorization?;
    end_session?;
    introspection?;
    registration?;
    revocation?;
    token?;
    userinfo?;
  };
  scopes?: ("openid" | "offline_access")[];
  subjectTypes?: ("public" | "pairwise")[];
  ttl: {
    AccessToken?: number;
    AuthorizationCode?: number;
    ClientCredentials?: number;
    DeviceCode?: number;
    IdToken?: number;
    RefreshToken?: number;
  };
}

interface IConfigurationFeatures {
  alwaysIssueRefresh?: boolean;
  backchannelLogout?: boolean;
  certificateBoundAccessTokens?: boolean;
  claimsParameter?: boolean;
  clientCredentials?: boolean;
  conformIdTokenClaims?: boolean;
  deviceFlow?:
  | boolean
  | { charset?: "base-20" | "digits"; mask?: "-" | "*" | " "; deviceInfo };
  devInteractions?: boolean;
  discovery?: boolean;
  encryption?: boolean;
  frontchannelLogout?: boolean;
  introspection?: boolean;
  jwtIntrospection?: boolean;
  jwtResponseModes?: boolean;
  oauthNativeApps?: boolean;
  pkce?:
  | boolean
  | { forcedForNative: boolean; supportedMethods: ("plain" | "S256")[] };
  registration?: boolean | { policies; initialAccessToken };
  registrationManagement?: boolean;
  requestUri?: boolean | { requireRequestUriRegistration: boolean };
  resourceIndicators?: boolean;
  request?: boolean;
  revocation?: boolean;
  sessionManagement?: boolean;
  webMessageResponseMode?: boolean;
}


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
    clients?: ClientMetadata[];
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
      clients: Provider.Client[];
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

  class Client  {
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
    metadata(): ClientMetadata;

    // method getters
    readonly sectorIdentifier;
    keystore?; // !!! keystore.refresh() !!! keystore.get({alg, use})
  }

}
export = Provider;
