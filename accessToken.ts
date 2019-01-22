import { BaseToken } from "./baseToken";
import { ISetAudiences, CertBound } from "./format";

export type AccessToken = BaseToken & ISetAudiences & CertBound;

export interface IAccessToken {
  constructor(data: {
    client;
    gty: "authorization_code" | "device_code" | "refresh_token";
    accountId;
    claims;
    grantId;
    scope;
    sid;
  }): AccessToken;
}
