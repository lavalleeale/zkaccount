import { createHash, createPrivateKey, createPublicKey, sign, type JsonWebKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { poseidon2Hash } from "@zkpassport/poseidon2";

const circuitDir = resolve(import.meta.dirname, "../google_jwt");
const variant = process.argv[2] ?? "valid";
const privateKey = createPrivateKey(
  readFileSync(resolve(circuitDir, "tests/fixtures/rsa-private.pem"), "utf8"),
);
const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as JsonWebKey;
if (!jwk.n || jwk.e !== "AQAB")
  throw new Error("Fixture must be a 2048-bit RSA key with exponent 65537");

const MAX_HEADER = 96;
const MAX_PAYLOAD = 735;
const MAX_AUDIENCE = 128;
const MAX_SUBJECT = 64;
const DOMAIN_IDENTITY = 0x474f4f474c455f343333375f49445f5631n;
const ISSUER_ID = 0x68747470733a2f2f6163636f756e74732e676f6f676c652e636f6dn;
const chainId = 84532n;
const factory = 0x1111111111111111111111111111111111111111n;
const device = 0x2222222222222222222222222222222222222222n;
const validUntil = variant === "expired" ? 2_000_000_500n : 2_000_000_000n;
const audience = "fixture.apps.googleusercontent.com";
const subject = "109876543210987654321";
const issuedAt = 1_999_999_700n;
const randomness = Uint8Array.from({ length: 32 }, (_, index) => index);

function base64UrlBytes(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function toBytes(value: bigint, length: number): Buffer {
  return Buffer.from(value.toString(16).padStart(length * 2, "0"), "hex");
}

function loginNonce(): string {
  const preimage = Buffer.concat([
    Buffer.from("GOOGLE_4337_LOGIN_V1"),
    toBytes(chainId, 32),
    toBytes(factory, 20),
    toBytes(device, 20),
    toBytes(validUntil, 8),
    randomness,
  ]);
  return `0x${createHash("sha256").update(preimage).digest("hex")}`;
}

function pad(bytes: Uint8Array, length: number): number[] {
  if (bytes.length > length) throw new Error(`Fixture length ${bytes.length} exceeds ${length}`);
  return [...bytes, ...new Array(length - bytes.length).fill(0)];
}

function splitLimbs(value: bigint): bigint[] {
  const mask = (1n << 120n) - 1n;
  return Array.from({ length: 18 }, (_, index) => (value >> BigInt(index * 120)) & mask);
}

function low248Sha(bytes: Uint8Array): bigint {
  const digest = createHash("sha256").update(bytes).digest();
  digest[0] = 0;
  return BigInt(`0x${digest.toString("hex")}`);
}

function packSubject(value: Uint8Array): [bigint, bigint, bigint] {
  const fields: [bigint, bigint, bigint] = [0n, 0n, 0n];
  value.forEach((byte, index) => {
    const chunk = Math.floor(index / 31) as 0 | 1 | 2;
    fields[chunk] = fields[chunk] * 256n + BigInt(byte);
  });
  return fields;
}

function quote(value: bigint | number): string {
  return `"0x${BigInt(value).toString(16)}"`;
}

function array(values: readonly (bigint | number)[]): string {
  return `[${Array.from(values, (value) => quote(value)).join(", ")}]`;
}

const headerText = JSON.stringify({
  alg: variant === "wrong_alg" ? "HS256" : "RS256",
  kid: "fixture",
  typ: "JWT",
});
const payloadText = JSON.stringify({
  iss: variant === "wrong_issuer" ? "https://issuer.example" : "https://accounts.google.com",
  aud: audience,
  sub: subject,
  nonce: loginNonce(),
  iat: Number(issuedAt),
  exp: 2_000_000_300,
});
const encodedHeader = Buffer.from(headerText).toString("base64url");
const encodedPayload = Buffer.from(payloadText).toString("base64url");
const signingInput = `${encodedHeader}.${encodedPayload}`;
const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey);

const modulus = base64UrlBytes(jwk.n);
if (modulus.length !== 256) throw new Error(`Expected a 256-byte modulus, got ${modulus.length}`);
const modulusValue = BigInt(`0x${modulus.toString("hex")}`);
const signatureValue = BigInt(`0x${signature.toString("hex")}`);
const redc = (1n << 4102n) / modulusValue;
const audienceBytes = Buffer.from(audience);
const subjectBytes = Buffer.from(subject);
const subjectFields = packSubject(subjectBytes);
const identity = poseidon2Hash([
  DOMAIN_IDENTITY,
  ISSUER_ID,
  ...subjectFields,
  BigInt(subjectBytes.length),
]);
const keyPreimage = Buffer.concat([
  Buffer.from("GOOGLE_RSA_KEY_V1"),
  Buffer.from([1, 0]),
  modulus,
  Buffer.from([0, 3, 1, 0, 1]),
]);

const entries: Record<string, string> = {
  device_address_bytes: array(toBytes(device, 20)),
  chain_id_bytes: array(toBytes(chainId, 32)),
  factory_address_bytes: array(toBytes(factory, 20)),
  valid_until_bytes: array(toBytes(validUntil, 8)),
  header: array(pad(Buffer.from(headerText), MAX_HEADER)),
  header_len: quote(Buffer.byteLength(headerText)),
  payload: array(pad(Buffer.from(payloadText), MAX_PAYLOAD)),
  payload_len: quote(Buffer.byteLength(payloadText)),
  audience: array(pad(audienceBytes, MAX_AUDIENCE)),
  audience_len: quote(audienceBytes.length),
  subject: array(pad(subjectBytes, MAX_SUBJECT)),
  subject_len: quote(subjectBytes.length),
  login_randomness: array(randomness),
  alg_offset: quote(headerText.indexOf('"alg"')),
  issuer_offset: quote(payloadText.indexOf('"iss"')),
  audience_offset: quote(payloadText.indexOf('"aud"')),
  subject_offset: quote(payloadText.indexOf('"sub"')),
  nonce_offset: quote(payloadText.indexOf('"nonce"')),
  iat_offset: quote(payloadText.indexOf('"iat"')),
  iat_len: quote(String(issuedAt).length),
  exp_offset: quote(payloadText.indexOf('"exp"')),
  exp_len: quote(String(2_000_000_300).length),
  modulus_bytes: array(modulus),
  modulus_limbs: array(splitLimbs(modulusValue)),
  redc_limbs: array(splitLimbs(redc)),
  signature_limbs: array(splitLimbs(signatureValue)),
  return: array([
    identity,
    low248Sha(audienceBytes),
    device,
    chainId,
    factory,
    validUntil,
    low248Sha(keyPreimage),
    issuedAt,
  ]),
};

const output = `${Object.entries(entries)
  .map(([key, value]) => `${key} = ${value}`)
  .join("\n")}\n`;
const outputPath = resolve(circuitDir, "Prover.toml");
writeFileSync(outputPath, output);
process.stdout.write(`Wrote deterministic fixture inputs to ${outputPath}\n`);

if (variant === "valid") {
  const nargo = process.env.NARGO_BIN ?? "nargo";
  const wrapper = process.env.ZK_BIN_WRAPPER;
  const command = wrapper ?? nargo;
  const args = wrapper ? [nargo, "execute", "fixture"] : ["execute", "fixture"];
  const result = spawnSync(command, args, { cwd: circuitDir, stdio: "inherit" });
  if (result.status !== 0) throw new Error("Failed to generate deterministic circuit witness");
}
