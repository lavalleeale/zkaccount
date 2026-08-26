import {
  bytesToHex,
  concat,
  encodeAbiParameters,
  getAddress,
  hexToBytes,
  isAddressEqual,
  isHex,
  keccak256,
  numberToHex,
  type Address,
  type Hex,
} from "viem";

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_ORDER = P256_ORDER / 2n;

export interface PublicDeviceKey {
  address: Address;
  publicKeyX: Hex;
  publicKeyY: Hex;
  rpId: string;
  rpIdHash: Hex;
}

export interface DeviceKey extends PublicDeviceKey {
  credentialId: Hex;
}

export interface PasskeyDeviceOptions {
  /** Stable, non-secret identifier that keeps each demo's credential distinct. */
  scope: string;
  displayName: string;
  rpId?: string;
}

/** Creates a discoverable ES256 passkey and returns only its public metadata. */
export async function createPasskeyDeviceKey(options: PasskeyDeviceOptions): Promise<DeviceKey> {
  assertPasskeySupport();
  const rpId = options.rpId ?? window.location.hostname;
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { id: rpId, name: "zkAccount" },
      user: {
        id: await sha256Bytes(
          new TextEncoder().encode(`ZKACCOUNT_WEBAUTHN_USER_V1:${options.scope}`),
        ),
        name: options.displayName,
        displayName: options.displayName,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      attestation: "none",
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey creation was cancelled");

  const response = credential.response as AuthenticatorAttestationResponse;
  const spki = response.getPublicKey?.();
  if (!spki) throw new Error("Authenticator did not expose an ES256 public key");
  const { x, y } = await parseP256PublicKey(spki);
  const rpIdHash = bytesToHex(await sha256Bytes(new TextEncoder().encode(rpId)));
  const authenticatorData = response.getAuthenticatorData?.();
  if (authenticatorData) {
    const actualRpIdHash = bytesToHex(new Uint8Array(authenticatorData).slice(0, 32));
    if (actualRpIdHash.toLowerCase() !== rpIdHash.toLowerCase()) {
      throw new Error("Passkey registration returned an unexpected RP ID hash");
    }
  }

  return normalizeDeviceKey({
    address: deviceIdentifier(x, y, rpIdHash),
    credentialId: bytesToHex(new Uint8Array(credential.rawId)),
    publicKeyX: x,
    publicKeyY: y,
    rpId,
    rpIdHash,
  });
}

/** Encodes the public half of a device as an uncompressed SEC1 P-256 point. */
export function encodeP256PublicKey(device: PublicDeviceKey): Hex {
  return concat(["0x04", device.publicKeyX, device.publicKeyY]);
}

/** Validates public redirect metadata and derives its canonical device identifier. */
export async function publicDeviceFromRpIdAndPublicKey(
  rpId: string,
  publicKey: string,
): Promise<PublicDeviceKey> {
  const normalizedRpId = normalizeRpId(rpId);
  if (!/^0x04[0-9a-fA-F]{128}$/.test(publicKey)) {
    throw new Error("P-256 public key must be an uncompressed 65-byte SEC1 point");
  }
  const publicKeyX = `0x${publicKey.slice(4, 68)}` as Hex;
  const publicKeyY = `0x${publicKey.slice(68, 132)}` as Hex;
  await validateP256Point(publicKeyX, publicKeyY);
  const rpIdHash = bytesToHex(await sha256Bytes(new TextEncoder().encode(normalizedRpId)));
  return {
    address: deviceIdentifier(publicKeyX, publicKeyY, rpIdHash),
    publicKeyX,
    publicKeyY,
    rpId: normalizedRpId,
    rpIdHash,
  };
}

/** Validates public passkey metadata loaded from application storage. */
export function loadPasskeyDeviceKey(value: unknown): DeviceKey {
  if (!isRecord(value)) throw new Error("Stored passkey metadata is missing");
  const candidate = value as Partial<DeviceKey>;
  if (
    typeof candidate.address !== "string" ||
    typeof candidate.credentialId !== "string" ||
    typeof candidate.publicKeyX !== "string" ||
    typeof candidate.publicKeyY !== "string" ||
    typeof candidate.rpId !== "string" ||
    typeof candidate.rpIdHash !== "string" ||
    !isHex(candidate.credentialId) ||
    !isBytes32(candidate.publicKeyX) ||
    !isBytes32(candidate.publicKeyY) ||
    !isBytes32(candidate.rpIdHash)
  ) {
    throw new Error("Stored passkey metadata is invalid");
  }
  if (normalizeRpId(candidate.rpId) !== candidate.rpId) {
    throw new Error("Stored passkey RP ID is invalid");
  }
  return normalizeDeviceKey(candidate as DeviceKey);
}

/** Creates the canonical mode-0 WebAuthn signature accepted by GoogleAccount. */
export async function signWithPasskey(device: DeviceKey, challenge: Hex): Promise<Hex> {
  assertPasskeySupport();
  if (!isBytes32(challenge)) throw new Error("WebAuthn challenge must be 32 bytes");
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(hexToBytes(challenge)),
      allowCredentials: [
        { type: "public-key", id: toArrayBuffer(hexToBytes(device.credentialId)) },
      ],
      userVerification: "required",
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey signing was cancelled");
  if (
    bytesToHex(new Uint8Array(credential.rawId)).toLowerCase() !== device.credentialId.toLowerCase()
  ) {
    throw new Error("Authenticator returned a different passkey");
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  const authenticatorData = new Uint8Array(response.authenticatorData);
  if (authenticatorData.length < 37) throw new Error("Authenticator data is malformed");
  if (bytesToHex(authenticatorData.slice(0, 32)).toLowerCase() !== device.rpIdHash.toLowerCase()) {
    throw new Error("Passkey assertion belongs to a different RP ID");
  }
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
    throw new Error("Passkey assertion did not verify user presence and identity");
  }
  if ((flags & 0x10) !== 0 && (flags & 0x08) === 0) {
    throw new Error("Passkey assertion contains invalid backup flags");
  }

  const clientDataJSON = new TextDecoder("utf-8", { fatal: true }).decode(response.clientDataJSON);
  const clientData = JSON.parse(clientDataJSON) as { type?: unknown; challenge?: unknown };
  const expectedChallenge = base64Url(hexToBytes(challenge));
  if (clientData.type !== "webauthn.get" || clientData.challenge !== expectedChallenge) {
    throw new Error("Passkey assertion is bound to a different challenge");
  }
  const typeIndex = clientDataJSON.indexOf('"type":"webauthn.get"');
  const challengeIndex = clientDataJSON.indexOf(`"challenge":"${expectedChallenge}"`);
  if (typeIndex < 0 || challengeIndex < 0) {
    throw new Error("Passkey client data is not in the supported JSON form");
  }
  const { r, s } = parseAndNormalizeP256Signature(new Uint8Array(response.signature));
  const encodedDevice = encodeAbiParameters([{ type: "address" }], [device.address]);
  const encodedAssertion = encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "bytes" },
      { type: "string" },
    ],
    [
      r,
      s,
      BigInt(challengeIndex),
      BigInt(typeIndex),
      bytesToHex(authenticatorData),
      clientDataJSON,
    ],
  );
  return concat(["0x00", encodedDevice, encodedAssertion]);
}

export function deviceIdentifier(publicKeyX: Hex, publicKeyY: Hex, rpIdHash: Hex): Address {
  if (!isBytes32(publicKeyX) || !isBytes32(publicKeyY) || !isBytes32(rpIdHash)) {
    throw new Error("WebAuthn device coordinates and RP ID hash must be 32 bytes");
  }
  const digest = keccak256(concat([publicKeyX, publicKeyY, rpIdHash]));
  return getAddress(`0x${digest.slice(-40)}`);
}

function normalizeDeviceKey(device: DeviceKey): DeviceKey {
  const expected = deviceIdentifier(device.publicKeyX, device.publicKeyY, device.rpIdHash);
  if (!isAddressEqual(device.address, expected)) {
    throw new Error("Stored passkey device identifier does not match its public key");
  }
  return { ...device, address: expected };
}

function normalizeRpId(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/\.$/, "");
  if (
    normalized.length === 0 ||
    normalized.length > 253 ||
    normalized.includes(":") ||
    normalized.includes("/") ||
    !/^[a-z0-9.-]+$/.test(normalized) ||
    normalized.startsWith(".") ||
    normalized.endsWith(".") ||
    normalized.includes("..")
  ) {
    throw new Error("RP ID must be a valid hostname without a port");
  }
  return normalized;
}

async function validateP256Point(x: Hex, y: Hex): Promise<void> {
  const toBase64Url = (value: Hex) => base64Url(hexToBytes(value));
  try {
    await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: toBase64Url(x), y: toBase64Url(y), ext: true },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new Error("Public key is not a valid P-256 curve point");
  }
}

async function parseP256PublicKey(spki: ArrayBuffer): Promise<{ x: Hex; y: Hex }> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new Error("Passkey did not create a P-256 public key");
  }
  const x = bytesToHex(fromBase64Url(jwk.x));
  const y = bytesToHex(fromBase64Url(jwk.y));
  if (!isBytes32(x) || !isBytes32(y)) throw new Error("Passkey returned invalid P-256 coordinates");
  return { x, y };
}

function parseAndNormalizeP256Signature(signature: Uint8Array): { r: Hex; s: Hex } {
  let offset = 0;
  if (signature[offset++] !== 0x30) throw new Error("Passkey signature is not a DER sequence");
  const sequenceLength = readDerLength(signature, offset);
  offset = sequenceLength.offset;
  if (sequenceLength.length !== signature.length - offset)
    throw new Error("Invalid DER sequence length");
  const first = readDerInteger(signature, offset);
  const second = readDerInteger(signature, first.offset);
  if (second.offset !== signature.length)
    throw new Error("Unexpected bytes after passkey signature");
  const rValue = bytesToBigInt(first.value);
  let sValue = bytesToBigInt(second.value);
  if (rValue <= 0n || rValue >= P256_ORDER || sValue <= 0n || sValue >= P256_ORDER) {
    throw new Error("Passkey signature scalar is out of range");
  }
  if (sValue > P256_HALF_ORDER) sValue = P256_ORDER - sValue;
  return { r: numberToHex(rValue, { size: 32 }), s: numberToHex(sValue, { size: 32 }) };
}

function readDerInteger(input: Uint8Array, start: number): { value: Uint8Array; offset: number } {
  if (input[start] !== 0x02) throw new Error("Passkey signature contains a non-integer value");
  const decoded = readDerLength(input, start + 1);
  const end = decoded.offset + decoded.length;
  if (decoded.length === 0 || end > input.length) throw new Error("Invalid DER integer length");
  let value = input.slice(decoded.offset, end);
  if ((value[0] & 0x80) !== 0) throw new Error("Passkey signature contains a negative integer");
  if (value.length > 1 && value[0] === 0) value = value.slice(1);
  if (value.length > 32) throw new Error("Passkey signature integer is too large");
  return { value, offset: end };
}

function readDerLength(input: Uint8Array, start: number): { length: number; offset: number } {
  if (start >= input.length) throw new Error("Missing DER length");
  const first = input[start];
  if (first < 0x80) return { length: first, offset: start + 1 };
  const lengthBytes = first & 0x7f;
  if (lengthBytes === 0 || lengthBytes > 2 || start + 1 + lengthBytes > input.length) {
    throw new Error("Unsupported DER length");
  }
  let length = 0;
  for (let i = 0; i < lengthBytes; i++) length = (length << 8) | input[start + 1 + i];
  return { length, offset: start + 1 + lengthBytes };
}

function bytesToBigInt(value: Uint8Array): bigint {
  return value.length === 0 ? 0n : BigInt(bytesToHex(value));
}

async function sha256Bytes(value: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(value)));
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function isBytes32(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function assertPasskeySupport(): void {
  if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("Passkeys require a secure context (HTTPS or localhost) and WebAuthn support");
  }
}
