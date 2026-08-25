# Circuit implementation

The circuit constrains:

1. base64url decoding and the exact signed `header.payload` bytes;
2. `alg`, `iss`, `aud`, `sub`, `nonce`, and `exp` extraction from those bytes;
3. SHA-256 plus RSA PKCS#1 v1.5 verification against the committed JWK;
4. the login challenge and all eight public inputs documented in the README.

The maintained zkpassport fork of `noir_rsa` is pinned at `v0.11.0` and the
compiler is Noir `1.0.0-beta.26`. The committed RSA key is test-only. The
fixture generator produces a canonical JWT and all 120-bit RSA/Barrett limbs;
the negative suite covers a signed expired token, signed wrong algorithm, signed
wrong issuer, and independent changes to subject, audience, nonce, signature,
modulus, signed payload, and public identity.

MVP bounds are explicit: RS256 with a 2048-bit modulus and exponent 65537,
128-byte header, 1024-byte payload, 128-byte audience, 64-byte subject, and
compact JSON claim fragments without whitespace between key, colon, and value.
