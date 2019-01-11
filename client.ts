export declare class Client {
  noManage: boolean;

  static cacheClear(id?: string): void;
  backchannelLogout(sub, sid);
}

export interface IClient {
  redirect_uris: string[];

  application_type?: "web" | "native";
  backchannel_logout_uri: string;
  backchannel_logout_session_required: boolean;
  client_name?: string;
  client_id: string;
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
  id_token_encrypted_response_alg?: string;
  id_token_encrypted_response_enc?: string;
  initiate_login_uri?: string;
  jwks?;
  jwks_uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  request_object_encryption_alg?: string;
  request_object_encryption_enc?: string;
  request_object_signing_alg?: string;
  request_uris: string[];
  require_auth_time?: boolean;
  response_types?: ("code" | "token" | "id_token")[];
  sector_identifier_uri?: string;
  subject_type?: "public" | "pairwise";
  tls_client_auth_subject_dn: string;
  tls_client_certificate_bound_access_tokens: boolean;
  token_endpoint_auth_method?:
    | "client_secret_post"
    | "client_secret_basic"
    | "client_secret_jwt"
    | "private_key_jwt"
    | "none";
  token_endpoint_auth_signing_alg?: string;
  tos_uri?: string;
  userinfo_signed_response_alg?: string;
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
