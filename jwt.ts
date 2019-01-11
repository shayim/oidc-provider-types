declare class JWT {
  static sign(payload, key, alg, signOptions);
  static encrypt(clearText, key, enc, alg, cty);
  static verify(jwt, keyOrStore, opts);
  static decode(jwt);
  static assertPayload(decoded, opts);
}
