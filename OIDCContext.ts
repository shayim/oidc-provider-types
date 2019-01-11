import { Context } from "koa";

export declare class OIDCContext {
  // properties
  ctx: Context;
  route: string; // ctx._matchedRouteName,  introspection
  authorization: object;
  redirectUriCheckPerformed: boolean;
  webMessageUriCheckPerformed: boolean;
  uuid: string; // ctx.params.grant) || uuid()
  entities: { AccessToken: { scope }; ClientCredentials; RefreshToken };
  claims: object;
  issuer: string; // provider.issuer

  // To find
  client;
  params: {
    scope;
    claims;
    cliend_id;
    prompt;
    response_mode;
    response_type;
    web_message_uri;
    web_message_target;
  };
  oidc: { body };
  signed; // with an array of parameter names which were received using a signed or	encrypted request/Uri parameter

  // methods
  entity(key, value): void; // set entities
  urlFor(
    name:
      | string
      | "authorization"
      | "certificates"
      | "check_session"
      | "client"
      | "code_verification"
      | "device_authorization"
      | "end_session"
      | "interaction"
      | "introspection"
      | "registration"
      | "revocation"
      | "submit"
      | "token"
      | "userinfo",
    opt: { grant: string; clientId: string; query: { user_code: string } }
  ): string;
  promptPending(name: string): boolean;

  // getters
  readonly requestParamClaims;
}
