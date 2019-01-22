import { IClient } from "./client";

export declare interface IClaims {
  // properties
  available: {}; // claims payload
  client: IClient;
  filter: {};

  // methods

  /// check Object.keys(this.filter).length ===0, otherwise scope cannot be assigned after mask has been set
  /// which means scope could only be set once
  /// set claims in this.filter
  scope(value?: string): IClaims;

  /// private set claims items
  mask(value): void;

  /// set claims off this.filter
  rejected(value?: string[]);

  /// return claims payload either value === null or object but not undefined filtered by this.filter
  /// with claims._claim_names and claims._claim.sources, if available
  /// if client.sectorIdentifier === true return claims.sub = pairwiseIdentifier(claims.sub, this.client)
  result(): Promise<any>;
}
