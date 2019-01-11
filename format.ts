export interface IOpaqueFormat {
  // for AccessToken, AuthorizationCode, RefreshToken, ClientCredentials, InitialAccessToken or RegistrationAccessToken
  jti?: string; // unique identifier of the token
  kind?: string; // token class name
  format?: string; // the format used for the token storage and representation
  exp?: number; //  timestamp of the token's expiration
  iat?: number; // timestamp of the token's creation
  iss?: string; // issuer identifier, useful in multi // provider instance apps
  accountId?: string; // account identifier the token belongs to
  clientId?: string; // client identifier the token belongs to
  aud?: string[]; // array of audiences the token is intended for
  authTime?: number; // timestamp of the end - user's authentication
  claims?: { rejected?: string[] }; // claims parameter(see claims in OIDC Core 1.0), rejected claims are, in addition, pushed in as an Array of Strings in the `rejected` property.
  codeChallenge?: string; // client provided PKCE code_challenge value
  codeChallengeMethod?: string; // client provided PKCE code_challenge_method value
  grantId?: string; // grant identifier, tokens with the same value belong together
  nonce?: string; // random nonce from an authorization request
  redirectUri?: string; // redirect_uri value from an authorization request
  scope?: string; // scope value from an authorization request, rejected scopes are removed from the value
  sid?: string; // session identifier the token comes from
  gty?: string; // [AccessToken, RefreshToken only] space delimited grant values, indicating the grant type(s) they originate from(implicit, authorization_code, refresh_token or device_code) the original one is always first, second is refresh_token if refreshed
  params?: {}; // [DeviceCode only] an object with the authorization request parameters as requested by the client with device_authorization_endpoint
  deviceInfo?: {}; // [DeviceCode only] an object with details about the device_authorization_endpoint request
  error?: string; // [DeviceCode only] - error from authnz to be returned to the polling client
  errorDescription?: string; // [DeviceCode only] - error_description from authnz to be returned to the polling client
}

export interface IJwtFormat extends IOpaqueFormat {
  jwt?: string; // the jwt value returned to the client
}

export interface IInteractionResult {
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
