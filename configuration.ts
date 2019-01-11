export interface IConfiguration {
  acrValues?: string[];
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
    | { charset?: "base-20" | "digits"; mask?: "-" | "*" | " " };
  devInteractions?: boolean;
  discovery?: boolean;
  encryption?: boolean;
  frontchannelLogout?: boolean;
  introspection?: boolean;
  jwtIntrospection?: boolean;
  jwtResponseModes?: boolean;
  oauthNativeApps?: boolean;
  pkce?: boolean | { supportedMethods: ("plain" | "S256")[] };
  registration?: boolean | { policies; initialAccessToken };
  registrationManagement?: boolean;
  requestUri?: boolean | { requireRequestUriRegistration: boolean };
  resourceIndicators?: boolean;
  request?: boolean;
  revocation?: boolean;
  sessionManagement?: boolean;
  webMessageResponseMode?: boolean;
}
