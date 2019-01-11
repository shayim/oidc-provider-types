export interface IInteractionSession {
  accountId: string;
  returnTo: string;
  interaction: { error?; reason?; description? };
  exp: number;
  uuid: string;
  params: {};
  signed: [];
  result: {};
}
