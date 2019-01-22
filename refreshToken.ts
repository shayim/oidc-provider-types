import { BaseToken } from "./baseToken";
import { Consumable } from "./consumable";

export type RefreshToekn = BaseToken & Consumable;

export interface IRefreshToken {
  constructor(data: {
    gty;
    accountId;
    arc;
    amr;
    authTime;
    claims;
    client;
    grantId;
    nonce;
    scope;
    resource;
    sid;
  }): RefreshToekn;
}
