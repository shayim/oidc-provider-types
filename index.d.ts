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
  /* @ mustChange
   *
   * description: Function used by the OP when resolving pairwise ID Token and Userinfo sub claim values.
   *
   * See [Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.8.1)
   *
   * affects: pairwise ID Token and Userinfo sub claim values
   *
   * recommendation: Since this might be called several times in one request with the same arguments, consider using memoization or otherwise caching the result based on account and client ids.
   *
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
  pairwiseIdentifier?(
    accountId: string,
    client: Provider.Client
  ): Promise<string>;

  /* @ mustChange
   *
   * description: Function resolving whether a given value with expiration is presented first time
   *
   * affects: client_secret_jwt and private_key_jwt client authentications
   *
   * recommendation: configure this option to use a shared store if client_secret_jwt and private_key_jwt are used
   *
   * default implementation
   * {
      if (cache.get(jti)) return false;
      cache.set(jti, true, (expiresAt - epochTime()) * 1000);
      return true;
   * }
   */
  uniqueness(
    ctx: Koa.Context,
    jti: string,
    expiresAt: number
  ): Promise<boolean>;

  /* @ mustChange
   *
   * description: Helper used by the OP to load an account and retrieve its available claims. The return value should be a Promise and #claims() can return a Promise too
   *
   * affects: authorization, authorization_code and refresh_token grants, ID Token claims
   *
   * default implementation
    {
      return {
        accountId: sub,

        // @param use {string} - can either be "id_token" or "userinfo", depending on where the specific claims are intended to be put in
        // @param scope {string} - the intended scope, while oidc-provider will mask claims depending on the scope automatically you might want to skip loading some claims from external resources or through db projection etc. based on this detail or not return them in ID Tokens but only UserInfo and so on
        // @param claims {object} - the part of the claims authorization parameter for either "id_token" or "userinfo" (depends on the "use" param)
        // @param rejected {Array[String]} - claim names that were rejected by the end-user, you might want to skip loading some claims from external resources or through db projection
        async claims(use, scope, claims, rejected) {
          return { sub };
        },
    };
  }
   */
  findById(
    ctx: Koa.Context,
    sub: string,
    token: any
  ): Promise<Provider.Account>;

  /* @shouldChange
   *
   * description: Helper used by the OP to determine where to redirect User-Agent for necessary interaction, can return both absolute and relative urls
   *
   * affects: authorization interactions
   *
   * defaut implementation
   *
   * {
        return `/interaction/${ctx.oidc.uuid}`;
   * }
   */
  interactionUrl?(ctx: Koa.Context, interaction: any): Promise<string>;

  /* @ shouldChange
   *
   * description: URL to which the OP redirects the User-Agent when no post_logout_redirect_uri is provided by the RP
   *
   * affects: session management
   *
   * default implementation
     {
      return ctx.origin;
     }
   */
  postLogoutRedirectUri?(ctx: Koa.Context): Promise<string>;

  /* @ shouldChange
   *
   * description: HTML source rendered when when session management feature renders a confirmation prompt for the User-Agent.
   *
   * affects: session management
   *
   * @param ctx - koa request context
   * @param form - form source (id="op.logoutForm") to be embedded in the page and submitted by the End-User
   *
   * default implementation
   *  {
        ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>Logout Request</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
          @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);button,h1{text-align:center}h1{font-weight:100;font-size:1.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}button{font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;width:100%;display:block;margin-bottom:10px;position:relative;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Do you want to sign-out from ${ctx.host}?</h1>
            <script>
              function logout() {
                var form = document.getElementById('op.logoutForm');
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'logout';
                input.value = 'yes';
                form.appendChild(input);
                form.submit();
              }
              function rpLogoutOnly() {
                var form = document.getElementById('op.logoutForm');
                form.submit();
              }
            </script>
            ${form}
            <button onclick="logout()">Yes, sign me out</button>
            <button onclick="rpLogoutOnly()">No, stay signed in</button>
          </div>
        </body>
        </html>`;
  }
   */
  logoutSource?(ctx: Koa.Context, form: string): Promise<void>;

  /* @ shouldChange
   *
   * description: HTML source rendered when device code feature renders an input prompt for the User-Agent.
   *
   * affects: device code input
   *
   * @param ctx - koa request context
   * @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and submitted by the End-User.
   * @param deviceInfo - device information from the device_authorization_endpoint call
   *
   * default implementation
   * {
        let msg;
        if (err && (err.userCode || err.name === 'NoCodeError')) {
          msg = '<p class="red">The code you entered is incorrect. Try again</p>';
        } else if (err) {
          msg = '<p class="red">There was an error processing your request</p>';
        } else {
          msg = '<p>Enter the code displayed on your device</p>';
        }
        ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>Sign-in</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
            @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}p.red{color:#d50000}input[type=email],input[type=password],input[type=text]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;text-align:center;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}[type=submit]:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Sign-in</h1>
            ${msg}
            ${form}
            <button type="submit" form="op.deviceInputForm">Continue</button>
          </div>
        </body>
        </html>`;
      }
  */
  userCodeInputSource?(
    ctx: Koa.Context,
    form: string,
    out: any,
    err: any
  ): Promise<void>;

  /* @ shouldChange
   *
   * description: HTML source rendered when device code feature renders an a confirmation prompt for the User-Agent.
   *
   * affects: device code authorization confirmation
   *
   * @param ctx - koa request context
   * @param form - form source (id="op.deviceConfirmForm") to be embedded in the page and submitted by the End-User.
   * @param deviceInfo - device information from the device_authorization_endpoint call

   * default implementation
   * {
        const {
          clientId,
          clientName,
          clientUri,
          logoUri,
          policyUri,
          tosUri, // eslint-disable-line no-unused-vars, max-len
        } = ctx.oidc.client;
        ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>Device Login Confirmation</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
            @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);.help,h1,h1+p{text-align:center}h1,h1+p{font-weight:100}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative;font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe;cursor:pointer}button:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}a{text-decoration:none;color:#666;font-weight:400;display:inline-block;opacity:.6}.help{width:100%;font-size:12px}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Confirm Device</h1>
            <p>
              You are about to authorize a <code>${clientName
                || clientId}</code> device client on IP <code>${deviceInfo.ip}</code>, identified by <code>${
          deviceInfo.userAgent
        }</code>
              <br/><br/>
              If you did not initiate this action and/or are unaware of such device in your possession please close this window.
            </p>
            ${form}
            <button autofocus type="submit" form="op.deviceConfirmForm">Continue</button>
            <div class="help">
              <a href="">[ Cancel ]</a>
            </div>
          </div>
        </body>
        </html>`;
    }
   */
  userCodeConfirmSource?(
    ctx: Koa.Context,
    form: string,
    client: Provider.Client,
    deviceInfo: any
  ): Promise<void>;

  /* @ shouldChange

   * description: HTML source rendered when device code feature renders a success page for the User-Agent.

   * affects: device code success page
   *
   * default implementation
   *
   *  {
            // @param ctx - koa request context
            const {
              clientId,
              clientName,
              clientUri,
              initiateLoginUri,
              logoUri,
              policyUri,
              tosUri, // eslint-disable-line no-unused-vars, max-len
            } = ctx.oidc.client;
            ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>Sign-in Success</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
            @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Sign-in Success</h1>
            <p>Your login ${
          clientName ? `with ${clientName}` : ''
        } was successful, you can now close this page.</p>
          </div>
        </body>
        </html>`;
      }
  */
  deviceFlowSuccess?(ctx: Koa.Context): Promise<void>;

  /* @ shouldChange
   *
   * description: HTML source rendered when there are pending front-channel logout iframes to be called to trigger RP logouts. It should handle waiting for the frames to be loaded as well as have a timeout mechanism in it.
   *
   * affects: session management
   *
   * default implementation
   * {

        ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>Logout</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
            iframe{visibility:hidden;position:absolute;left:0;top:0;height:0;width:0;border:none}
          </style>
        </head>
        <body>
          ${frames.join('')}
          <script>
            var loaded = 0;
            function redirect() {
              window.location.replace("${postLogoutRedirectUri}");
            }
            function frameOnLoad() {
              loaded += 1;
              if (loaded === ${frames.length}) redirect();
            }
            Array.prototype.slice.call(document.querySelectorAll('iframe')).forEach(function (element) {
              element.onload = frameOnLoad;
            });
            setTimeout(redirect, ${timeout});
          </script>
        </body>
        </html>`;
      }
   */
  frontchannelLogoutPendingSource?(
    ctx: Koa.Context,
    frames,
    postLogoutRedirectUri,
    timeout
  ): Promise<void>;

  /* @ shouldChange
   *
   * description: Helper used by the OP to present errors to the User-Agent
   *
   * affects: presentation of errors encountered during End-User flows
   *
   * defaut implementation
   *
   * {
        ctx.type = 'html';
        ctx.body = `<!DOCTYPE html>
        <head>
          <meta charset="utf-8">
          <title>oops! something went wrong</title>
          <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
          <meta http-equiv="x-ua-compatible" content="ie=edge">
          <style>
            @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1{font-weight:100;text-align:center;font-size:2.3em}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}pre{white-space:pre-wrap;white-space:-moz-pre-wrap;white-space:-pre-wrap;white-space:-o-pre-wrap;word-wrap:break-word;margin:0 0 0 1em;text-indent:-1em}
          </style>
        </head>
        <body>
          <div class="container">
            <h1>oops! something went wrong</h1>
            ${Object.entries(out)
            .map(([key, value]) => `<pre><strong>${key}</strong>: ${value}</pre>`)
            .join('')}
          </div>
        </body>
        </html>`;
    }
 */
  renderError?(ctx: Koa.Context, out: any, error: any): Promise<void>;

  acrValues?: string[];
  audiences(ctx, sub, token, use): Promise<string[]>;
  claims?: { [key: string]: string[] | { [key: string]: null } };
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

  // @double-check
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
  extraClientMetadata?: {
    properties: string[];
    validator?(key, value, metadata): void;
  };
  extraParams?: string[] | Set<string>;
  features?: IConfigurationFeatures;

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
  interactionCheck(ctx: Koa.Context): any;
  interactionUrl?(ctx, interaction): string;
  prompts?: ("consent" | "login" | "none")[];
  refreshTokenRotation?:'none'| 'rotateAndConsume'
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
  tokenEndpointAuthMethods?: string[];
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

  // @double-check
  deviceFlow?:
    | boolean
    | { charset?: "base-20" | "digits"; mask?: "-" | "*" | " "; deviceInfo };

  devInteractions: boolean;
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

  // @double-check
  registration?:
    | boolean
    | {
        initialAccessToken: boolean;
        policies?: {
          [key: string]: (ctx: Koa.Context, properties: any) => any;
        };
      };

  registrationManagement?: boolean | { rotateRegistrationAccessToken: boolean };
  requestUri?: boolean | { requireRequestUriRegistration: boolean };

  resourceIndicators?: boolean;
  request?: boolean;
  revocation?: boolean;
  sessionManagement?:
    | boolean
    | { keepHeaders: boolean; thirdPartyCheckUrl: string };
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

  interface Claims {
    // properties
    available: {}; // claims payload
    client: Client;
    filter: {};

    // methods

    /// check Object.keys(this.filter).length ===0, otherwise scope cannot be assigned after mask has been set
    /// which means scope could only be set once
    /// set claims in this.filter
    scope(value?: string): Claims;

    /// private set claims items
    mask(value): void;

    /// set claims off this.filter
    rejected(value?: string[]);

    /// return claims payload either value === null or object but not undefined filtered by this.filter
    /// with claims._claim_names and claims._claim.sources, if available
    /// if client.sectorIdentifier === true return claims.sub = pairwiseIdentifier(claims.sub, this.client)
    result(): Promise<any>;
  }

  interface Account {
    accountId: string;

    claims(
      use: "id_token" | "userinfo",
      scope: string,
      claims: object,
      rejected: string[]
    ): Promise<Claims>;
  }

  class Client {
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
