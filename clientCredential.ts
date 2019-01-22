import { BaseToken, ISetAudiences, CertBound } from "./format";

export type ClientCredential = BaseToken & ISetAudiences & CertBound;
