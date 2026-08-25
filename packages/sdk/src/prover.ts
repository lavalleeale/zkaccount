import { BackendType, Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { poseidon2HashAsync } from "@zkpassport/poseidon2";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import circuitArtifact from "./generated/google_jwt.json";
import type { GoogleLoginResult } from "./google";

const MAX_HEADER = 128;
const MAX_PAYLOAD = 1024;
const MAX_AUDIENCE = 128;
const MAX_SUBJECT = 64;
const DOMAIN_IDENTITY = 0x474f4f474c455f343333375f49445f5631n;
const ISSUER_ID = 0x68747470733a2f2f6163636f756e74732e676f6f676c652e636f6dn;

export interface GoogleProof {
  proof: Hex;
  publicInputs: readonly Hex[];
}

interface GoogleJwk {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

interface ParsedToken {
  headerText: string;
  payloadText: string;
  header: { alg: string; kid: string };
  signature: Uint8Array;
}

export async function proveGoogleAuthorization(
  login: GoogleLoginResult,
): Promise<GoogleProof> {
  const inputs = await buildGoogleCircuitInputs(login);
  const noir = new Noir(circuitArtifact as CompiledCircuit);
  const { witness } = await noir.execute(inputs);
  const api = await Barretenberg.new({
    backend: BackendType.Wasm,
    threads: 4,
    // Values are 64 KiB WebAssembly pages: start at 64 MiB and permit growth
    // to 2 GiB for the ~331k-gate RSA/JWT circuit.
    memory: { initial: 1024, maximum: 32768 },
  });
  try {
    const backend = new UltraHonkBackend(circuitArtifact.bytecode, api);
    const result = await backend.generateProof(witness, {
      verifierTarget: "evm",
    });
    return {
      proof: bytesToHex(result.proof),
      publicInputs: result.publicInputs.map(normalizeField),
    };
  } finally {
    await api.destroy();
  }
}

export async function buildGoogleCircuitInputs(
  login: GoogleLoginResult,
): Promise<InputMap> {
  const parsed = parseRawToken(login.idToken);
  if (parsed.header.alg !== "RS256")
    throw new Error("Google token does not use RS256");
  if (login.claims.iss !== "https://accounts.google.com")
    throw new Error("Unsupported Google issuer");
  if (!login.claims.sub || login.claims.sub.length > MAX_SUBJECT)
    throw new Error("Google subject is missing or too long");
  if (login.claims.aud.length > MAX_AUDIENCE)
    throw new Error("Google audience is too long");
  if (login.claims.exp < login.challenge.proofExpiry)
    throw new Error("Google token expires before the proof authorization");

  const jwk = await fetchGoogleJwk(parsed.header.kid);
  if (jwk.e !== "AQAB")
    throw new Error("Only Google RSA exponent 65537 is supported");
  const modulus = fromBase64Url(jwk.n);
  if (modulus.length !== 256)
    throw new Error("Only 2048-bit Google RSA keys are supported");

  const headerBytes = new TextEncoder().encode(parsed.headerText);
  const payloadBytes = new TextEncoder().encode(parsed.payloadText);
  const audienceBytes = new TextEncoder().encode(login.claims.aud);
  const subjectBytes = new TextEncoder().encode(login.claims.sub);
  if (headerBytes.length > MAX_HEADER || payloadBytes.length > MAX_PAYLOAD) {
    throw new Error("Google token exceeds the circuit's bounded JWT size");
  }

  const modulusValue = bytesToBigInt(modulus);
  const redc = (1n << 4102n) / modulusValue;
  const subjectFields = packSubject(subjectBytes);
  const identity = await poseidon2HashAsync([
    DOMAIN_IDENTITY,
    ISSUER_ID,
    ...subjectFields,
    BigInt(subjectBytes.length),
  ]);
  const audienceHash = await low248Sha(audienceBytes);
  const keyHash = await googleKeyCommitment(modulus);
  const device = BigInt(login.challenge.deviceAddress);
  const factory = BigInt(login.challenge.factory);
  const chainId = BigInt(login.challenge.chainId);
  const validUntil = BigInt(login.challenge.proofExpiry);

  return {
    device_address: field(device),
    device_address_bytes: byteInputs(bigIntToBytes(device, 20)),
    chain_id: field(chainId),
    chain_id_bytes: byteInputs(bigIntToBytes(chainId, 32)),
    factory_address: field(factory),
    factory_address_bytes: byteInputs(bigIntToBytes(factory, 20)),
    valid_until: field(validUntil),
    valid_until_bytes: byteInputs(bigIntToBytes(validUntil, 8)),
    header: byteInputs(pad(headerBytes, MAX_HEADER)),
    header_len: headerBytes.length,
    payload: byteInputs(pad(payloadBytes, MAX_PAYLOAD)),
    payload_len: payloadBytes.length,
    audience: byteInputs(pad(audienceBytes, MAX_AUDIENCE)),
    audience_len: audienceBytes.length,
    subject: byteInputs(pad(subjectBytes, MAX_SUBJECT)),
    subject_len: subjectBytes.length,
    login_randomness: byteInputs(hexToBytes(login.challenge.loginRandomness)),
    alg_offset: requiredOffset(parsed.headerText, '"alg":"RS256"'),
    issuer_offset: requiredOffset(
      parsed.payloadText,
      '"iss":"https://accounts.google.com"',
    ),
    audience_offset: requiredOffset(
      parsed.payloadText,
      `"aud":"${login.claims.aud}"`,
    ),
    subject_offset: requiredOffset(
      parsed.payloadText,
      `"sub":"${login.claims.sub}"`,
    ),
    nonce_offset: requiredOffset(
      parsed.payloadText,
      `"nonce":"${login.challenge.nonce}"`,
    ),
    exp_offset: requiredOffset(parsed.payloadText, `"exp":${login.claims.exp}`),
    exp_len: String(login.claims.exp).length,
    modulus_bytes: byteInputs(modulus),
    modulus_limbs: limbInputs(modulusValue),
    redc_limbs: limbInputs(redc),
    signature_limbs: limbInputs(bytesToBigInt(parsed.signature)),
    return: [
      identity,
      audienceHash,
      device,
      chainId,
      factory,
      validUntil,
      keyHash,
      1n,
    ].map(field),
  };
}

function parseRawToken(token: string): ParsedToken {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed Google ID token");
  const headerText = new TextDecoder().decode(fromBase64Url(parts[0]));
  const payloadText = new TextDecoder().decode(fromBase64Url(parts[1]));
  return {
    headerText,
    payloadText,
    header: JSON.parse(headerText) as { alg: string; kid: string },
    signature: fromBase64Url(parts[2]),
  };
}

async function fetchGoogleJwk(kid: string): Promise<GoogleJwk> {
  const response = await fetch("https://www.googleapis.com/oauth2/v3/certs", {
    cache: "no-cache",
  });
  if (!response.ok)
    throw new Error(`Google JWKS request failed: ${response.status}`);
  const { keys } = (await response.json()) as { keys: GoogleJwk[] };
  const key = keys.find(
    (candidate) =>
      candidate.kid === kid &&
      candidate.kty === "RSA" &&
      candidate.alg === "RS256" &&
      candidate.use === "sig",
  );
  if (!key)
    throw new Error(`Google signing key ${kid} is not in the current JWKS`);
  return key;
}

async function googleKeyCommitment(modulus: Uint8Array): Promise<bigint> {
  return low248Sha(
    new Uint8Array([
      ...new TextEncoder().encode("GOOGLE_RSA_KEY_V1"),
      1,
      0,
      ...modulus,
      0,
      3,
      1,
      0,
      1,
    ]),
  );
}

async function low248Sha(bytes: Uint8Array): Promise<bigint> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)),
  );
  digest[0] = 0;
  return bytesToBigInt(digest);
}

function packSubject(subject: Uint8Array): [bigint, bigint, bigint] {
  const fields: [bigint, bigint, bigint] = [0n, 0n, 0n];
  subject.forEach((byte, index) => {
    const chunk = Math.floor(index / 31) as 0 | 1 | 2;
    fields[chunk] = fields[chunk] * 256n + BigInt(byte);
  });
  return fields;
}

function splitLimbs(value: bigint): bigint[] {
  const mask = (1n << 120n) - 1n;
  return Array.from(
    { length: 18 },
    (_, index) => (value >> BigInt(index * 120)) & mask,
  );
}

function limbInputs(value: bigint): string[] {
  return splitLimbs(value).map(field);
}
function field(value: bigint | number): string {
  return `0x${BigInt(value).toString(16)}`;
}
function normalizeField(value: string): Hex {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}
function byteInputs(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

function pad(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length > length)
    throw new Error(
      `Input length ${bytes.length} exceeds circuit bound ${length}`,
    );
  const result = new Uint8Array(length);
  result.set(bytes);
  return result;
}

function requiredOffset(text: string, fragment: string): number {
  const offset = text.indexOf(fragment);
  if (offset < 0)
    throw new Error(
      `JWT does not contain circuit-compatible claim encoding: ${fragment.slice(0, 20)}`,
    );
  return offset;
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(
    normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="),
  );
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(bytesToHex(bytes));
}
function bigIntToBytes(value: bigint, length: number): Uint8Array {
  return hexToBytes(`0x${value.toString(16).padStart(length * 2, "0")}`);
}
