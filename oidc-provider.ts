import { EventEmitter } from 'events'
import * as Koa from 'koa'

interface IConfiguration {
  acrValues?: string[]
  claims?: { [key: string]: string[] | { [key: string]: null } } //{ amr?; address?; email?; phone?; profile? }
  clientCacheDuration?: number
  clockTolerance?: number
  cookies?: {
    names?: { session?: string; interaction?: string; resume?: string; state?: string }
    long?: { secure?: boolean; signed?: boolean; httpOnly?: boolean; maxAge?: number }
    short?: { secure?: boolean; signed?: boolean; httpOnly?: boolean; maxAge?: number }
    keys?: string[]
  }
  discovery?: {
    acr_values_supported?: string[] | number[]
    claim_types_supported?: ('normal' | 'aggregated' | 'distributed')[]
    claims_locales_supported?
    display_values_supported?
    op_policy_uri?
    op_tos_uri?
    service_documentation?
    ui_locales_supported?
  }
  dynamicScopes?: string[]
  extraParams?: string[] | Set<string>
  features?: IConfigurationFeatures
  findById?: (
    ctx,
    sub: string,
    token
  ) => {
    accountId: string
    claims: (
      use: 'id_token' | 'userinfo',
      scope: string,
      claims: object,
      rejected: string[]
    ) => { sub }
  }
  formats?: {
    default?: 'opaque' | 'legacy'
    AccessToken?: 'opaque' | 'jwt' | Function
    AuthorizationCode?: 'opaque' | 'jwt' | Function
    Client?: 'opaque' | 'jwt' | Function
    ClientCredentials?: 'opaque' | 'jwt' | Function
    DeviceCode?: 'opaque' | 'jwt' | Function
    InitialAccessToken?: 'opaque' | 'jwt' | Function
    RefreshToken?: 'opaque' | 'jwt' | Function
    Session?: 'opaque' | 'jwt' | Function
  }
  interactionUrl?(ctx, interaction): string
  prompts?: ('consent' | 'login' | 'none')[]
  routes?: {
    authorization?
    certificates?
    check_session?
    code_verification?
    device_authorization?
    end_session?
    introspection?
    registration?
    revocation?
    token?
    userinfo?
  }
  scopes?: ('openid' | 'offline_access')[]
  subjectTypes?: ('public' | 'pairwise')[]
  ttl: {
    AccessToken?: number
    AuthorizationCode?: number
    ClientCredentials?: number
    DeviceCode?: number
    IdToken?: number
    RefreshToken?: number
  }
}

interface IConfigurationFeatures {
  alwaysIssueRefresh?: boolean
  backchannelLogout?: boolean
  certificateBoundAccessTokens?: boolean
  claimsParameter?: boolean
  clientCredentials?: boolean
  conformIdTokenClaims?: boolean
  deviceFlow?: boolean | { charset?: 'base-20' | 'digits'; mask?: '-' | '*' | ' ' }
  devInteractions?: boolean
  discovery?: boolean
  encryption?: boolean
  frontchannelLogout?: boolean
  introspection?: boolean
  jwtIntrospection?: boolean
  jwtResponseModes?: boolean
  oauthNativeApps?: boolean
  pkce?: boolean | { supportedMethods: ('plain' | 'S256')[] }
  registration?: boolean | { policies; initialAccessToken }
  registrationManagement?: boolean
  requestUri?: boolean | { requireRequestUriRegistration: boolean }
  resourceIndicators?: boolean
  request?: boolean
  revocation?: boolean
  sessionManagement?: boolean
  webMessageResponseMode?: boolean
}

interface IProvider {
  defaultHttpOptions: { timeout?: number; headers?: {} }
}

interface IAdapter {
  constructor(
    name:
      | 'Session'
      | 'AccessToken'
      | 'AuthorizationCode'
      | 'RefreshToken'
      | 'ClientCredentials'
      | 'Client'
      | 'InitialAccessToken'
      | 'RegistrationAccessToken'
      | 'DeviceCode'
  )

  find(id: string): Promise<object | null>
  findByUserCode(userCode: string): Promise<object | null>
  upsert(
    id: string,
    payload: IOpaqueFormat | IJwtFormat | IClient | IOidcSession | IInteractionSession,
    expiresIn: number
  )
  consume(id): Promise<any>
  destroy(id): Promise<any>
}

interface IOidcSession {
  account: string
  authorizations: { sid }
  loginTs: number
  exp: number
}

interface IInteractionSession {
  accountId: string
  returnTo: string
  interaction: { error?; reason?; description? }
  exp: number
  uuid: string
  params: {}
  signed: []
  result: {}
}

interface IClient {
  redirect_uris: string[]

  application_type?: 'web' | 'native'
  backchannel_logout_uri: string
  backchannel_logout_session_required: boolean
  client_name?: string
  client_id: string
  client_secret: string
  client_uri?: string
  contacts: string[]
  default_acr_values?: string[]
  default_max_age?: number
  grant_types?: (
    | 'authorization_code'
    | 'client_credentials'
    | 'implicit'
    | 'refresh_token'
    | 'urn:ietf:params:oauth:grant-type:device_code')[]
  id_token_signed_response_alg?: string
  id_token_encrypted_response_alg?: string
  id_token_encrypted_response_enc?: string
  initiate_login_uri?: string
  jwks?
  jwks_uri?: string
  logo_uri?: string
  policy_uri?: string
  request_uris: string[]
  require_auth_time?: boolean
  request_object_signing_alg?: string
  request_object_encryption_alg?: string
  request_object_encryption_enc?: string
  response_types?: ('code' | 'token' | 'id_token')[]
  sector_identifier_uri?: string
  subject_type?: 'public' | 'pairwise'
  token_endpoint_auth_method?:
    | 'client_secret_post'
    | 'client_secret_basic'
    | 'client_secret_jwt'
    | 'private_key_jwt'
    | 'none'
  token_endpoint_auth_signing_alg?: string
  tos_uri?: string
  userinfo_signed_response_alg?: string
  userinfo_encrypted_response_alg?: string
  userinfo_encrypted_response_enc?: string
}

interface IOpaqueFormat {
  // for AccessToken, AuthorizationCode, RefreshToken, ClientCredentials, InitialAccessToken or RegistrationAccessToken
  jti?: string // unique identifier of the token
  kind?: string // token class name
  format?: string // the format used for the token storage and representation
  exp?: number //  timestamp of the token's expiration
  iat?: number //timestamp of the token's creation
  iss?: string // issuer identifier, useful in multi // provider instance apps
  accountId?: string // account identifier the token belongs to
  clientId?: string // client identifier the token belongs to
  aud?: string[] //array of audiences the token is intended for
  authTime?: number // timestamp of the end - user's authentication
  claims?: { rejected?: string[] } // claims parameter(see claims in OIDC Core 1.0), rejected claims are, in addition, pushed in as an Array of Strings in the `rejected` property.
  codeChallenge?: string // client provided PKCE code_challenge value
  codeChallengeMethod?: string // client provided PKCE code_challenge_method value
  grantId?: string // grant identifier, tokens with the same value belong together
  nonce?: string // random nonce from an authorization request
  redirectUri?: string // redirect_uri value from an authorization request
  scope?: string // scope value from an authorization request, rejected scopes are removed from the value
  sid?: string // session identifier the token comes from
  gty?: string // [AccessToken, RefreshToken only] space delimited grant values, indicating the grant type(s) they originate from(implicit, authorization_code, refresh_token or device_code) the original one is always first, second is refresh_token if refreshed
  params?: {} // [DeviceCode only] an object with the authorization request parameters as requested by the client with device_authorization_endpoint
  deviceInfo?: {} // [DeviceCode only] an object with details about the device_authorization_endpoint request
  error?: string // [DeviceCode only] - error from authnz to be returned to the polling client
  errorDescription?: string // [DeviceCode only] - error_description from authnz to be returned to the polling client
}

interface IJwtFormat extends IOpaqueFormat {
  jwt?: string // the jwt value returned to the client
}

interface IInteractionResult {
  login: {
    account: string // logged-in account id
    acr: string // acr value for the authentication
    remember: boolean // true if provider should use a persistent cookie rather than a session one
    ts: number // unix timestamp of the authentication
  }
  consent: {
    rejectedScopes: string[] // array of strings, scope names the end-user has not granted
    rejectedClaims: string[] // array of strings, claim names the end-user has not granted
  }
  meta: {}
}

declare class Provider extends EventEmitter {
  constructor(issuer: string, setup: IConfiguration)
  DeviceCode
  intialize(setup: { adapter?: IAdapter; clients?: IClient[]; keystore? }): Promise<void>
  interactionDetails(req)
  interactionFinished(req, res, result: IInteractionResult)
  interactionResult(req, res, result)
  pathFor(name: string, mountPath: string, opts: {}): string
  setProviderSession(
    req,
    res,
    payload: { account: string; ts: number; remember: boolean; clients: IClient[]; meta }
  )
  registerGrantType(name, handlerFactory, params, dupes): void
  use(fn: Koa.Middleware): void
  static useGot(): void
  static useRequest(): void
}

declare class BaseToken {
  jti: string
  kind: string // this.constructor.name
  clientId: string
  expiration: number

  constructor(jti: string, kind: string, payload: {})
  client: IClient
  readonly isValid: boolean
  readonly isExpired: boolean
  readonly remainingTTL: number

  save(): Promise<any>

  static expiresIn(...args): number | undefined
  static readonly IN_PAYLOAD: string[]
}

declare class IdToken {
  available: {}
  extra: {}
  client: IClient

  constructor(available: {}, client: IClient)
  static expiresIn(...args): number | undefined
}

declare class Client {
  noManage: boolean

  static cacheClear(id?: string): void
  backchannelLogout(sub, sid)
}

declare class Adapter {
  static connect(provider: Provider): Promise<any>
}

declare class OIDCContext {
  ctx: Koa.Context
  route: string // ctx._matchedRoute
  authorization: {}
  redirectUriCheckPerformed: boolean
  webMessageUriCheckPerformed: boolean
  uuid: string // (ctx.params && ctx.params.grant) || uuid()
  entities: {}
  claims: {}
  issuer: string // provider.issuer

  entity(key, value): void // set entities
  urlFor(name: string, opt: {}): string
  promptPending(name: string)
}
