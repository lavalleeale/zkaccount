import {
  bytesToBigInt,
  bytesToHex,
  concatBytes,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";

const DEVICE_KEY_DOMAIN = "ZKACCOUNT_PASSKEY_DEVICE_V1";
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface DeviceKey {
  address: Address;
  account: PrivateKeyAccount;
  protection: "passkey-prf" | "memory-only";
}

export interface PasskeyDeviceOptions {
  /** Stable, non-secret name that keeps Demo A and Demo B keys distinct. */
  scope: string;
  displayName: string;
}

interface PrfInput {
  prf: { eval: { first: Uint8Array<ArrayBuffer> } };
}

interface PrfOutput {
  prf?: { results?: { first?: ArrayBuffer } };
}

/** Creates a discoverable passkey and prepares its app-specific device key. */
export async function createPasskeyDeviceKey(options: PasskeyDeviceOptions): Promise<DeviceKey> {
  assertPasskeySupport();
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: "zkAccount" },
      user: {
        id: await scopeUserId(options.scope),
        name: options.displayName,
        displayName: options.displayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      attestation: "none",
      timeout: 120_000,
      extensions: await prfInput(options.scope),
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey creation was cancelled");
  const creationPrf = readPrfResult(credential);
  if (creationPrf) return deviceFromPrf(creationPrf, options.scope);

  // Some authenticators advertise PRF at registration but return its value only
  // during an assertion. Ask for the new credential explicitly in that case.
  return getPasskeyDeviceKey(options, [{ type: "public-key", id: credential.rawId }]);
}

/** Unlocks a discoverable passkey and prepares its app-specific device key. */
export async function unlockPasskeyDeviceKey(options: PasskeyDeviceOptions): Promise<DeviceKey> {
  return getPasskeyDeviceKey(options);
}

async function getPasskeyDeviceKey(
  options: PasskeyDeviceOptions,
  allowCredentials?: PublicKeyCredentialDescriptor[],
): Promise<DeviceKey> {
  assertPasskeySupport();
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials,
      userVerification: "required",
      timeout: 120_000,
      extensions: await prfInput(options.scope),
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey authentication was cancelled");
  if (!allowCredentials) {
    const response = credential.response as AuthenticatorAssertionResponse;
    const expectedUserId = await scopeUserId(options.scope);
    if (!response.userHandle || !equalBytes(new Uint8Array(response.userHandle), expectedUserId)) {
      throw new Error(`The selected passkey does not belong to ${options.displayName}`);
    }
  }
  const prf = readPrfResult(credential);
  if (prf) return deviceFromPrf(prf, options.scope);
  return createMemoryOnlyDeviceKey();
}

async function prfInput(scope: string): Promise<AuthenticationExtensionsClientInputs> {
  return {
    prf: {
      eval: { first: await domainSalt(`${DEVICE_KEY_DOMAIN}:PRF:${scope}`) },
    },
  } as AuthenticationExtensionsClientInputs & PrfInput;
}

function readPrfResult(credential: PublicKeyCredential): Uint8Array<ArrayBuffer> | undefined {
  const output = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs &
    PrfOutput;
  const first = output.prf?.results?.first;
  return first ? new Uint8Array(first) : undefined;
}

async function deviceFromPrf(prf: Uint8Array<ArrayBuffer>, scope: string): Promise<DeviceKey> {
  // PRF output is credential-bound key material. Domain-separate it once more
  // before interpreting it as a secp256k1 scalar.
  for (let counter = 0; counter < 256; counter++) {
    const input = new Uint8Array(
      concatBytes([
        stringToBytes(`${DEVICE_KEY_DOMAIN}:SECP256K1:${scope}:`),
        prf,
        new Uint8Array([counter]),
      ]),
    );
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    const scalar = bytesToBigInt(digest);
    if (scalar > 0n && scalar < SECP256K1_ORDER) {
      const account = privateKeyToAccount(bytesToHex(digest) as Hex);
      return {
        address: account.address,
        account,
        protection: "passkey-prf",
      };
    }
  }
  throw new Error("Could not derive a valid device key from this passkey");
}

function createMemoryOnlyDeviceKey(): DeviceKey {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return { address: account.address, account, protection: "memory-only" };
}

async function domainSalt(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(stringToBytes(value))),
  );
}

function scopeUserId(scope: string): Promise<Uint8Array<ArrayBuffer>> {
  return domainSalt(`${DEVICE_KEY_DOMAIN}:USER:${scope}`);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

function assertPasskeySupport(): void {
  if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("Passkeys require a secure context (HTTPS or localhost) and WebAuthn support");
  }
}
