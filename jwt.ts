export declare class JWT {
  static sign(
    payload: { aud; azp; exp; iss; sub },
    key,
    alg: "none",
    signOptions?: {
      audience?;
      authorizedParty?;
      expiresIn?;
      issuer?;
      subject?;
      noIat?;
    }
  );
  static encrypt(clearText, key, enc, alg, cty);
  static verify(jwt, keyOrStore, opts);
  static decode(jwt);
  static assertPayload(decoded, opts);
}
