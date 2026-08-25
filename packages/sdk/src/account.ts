import {
  bytesToBigInt,
  bytesToHex,
  concatBytes,
  hexToBytes,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";

const DEVICE_KEY_DOMAIN = "ZKACCOUNT_PASSKEY_DEVICE_V1";
const LOCAL_KEY_PREFIX = "zkaccount:passkey-device:v1";
const LOCAL_KEY_DATABASE = "zkaccount-passkey-device";
const LOCAL_KEY_STORE = "wrapping-keys";
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export interface DeviceKey {
  address: Address;
  account: PrivateKeyAccount;
  protection: "passkey-prf" | "local-encrypted";
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

interface EncryptedLocalDeviceKey {
  version: 1;
  iv: string;
  ciphertext: string;
}

/** Creates a discoverable passkey and prepares its app-specific device key. */
export async function createPasskeyDeviceKey(options: PasskeyDeviceOptions): Promise<DeviceKey> {
  assertPasskeySupport();
  const credential = await navigator.credentials.create({
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
  }) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey creation was cancelled");
  const creationPrf = readPrfResult(credential);
  if (creationPrf) return deviceFromPrf(creationPrf, options.scope);

  // Some authenticators advertise PRF at registration but return its value only
  // during an assertion. Ask for the new credential explicitly in that case.
  return getPasskeyDeviceKey(options, [{ type: "public-key", id: credential.rawId }]);
}

/** Unlocks a discoverable passkey and restores its app-specific device key. */
export async function unlockPasskeyDeviceKey(options: PasskeyDeviceOptions): Promise<DeviceKey> {
  return getPasskeyDeviceKey(options);
}

async function getPasskeyDeviceKey(
  options: PasskeyDeviceOptions,
  allowCredentials?: PublicKeyCredentialDescriptor[],
): Promise<DeviceKey> {
  assertPasskeySupport();
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials,
      userVerification: "required",
      timeout: 120_000,
      extensions: await prfInput(options.scope),
    },
  }) as PublicKeyCredential | null;

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

  const credentialId = base64Url(new Uint8Array(credential.rawId));
  return allowCredentials
    ? createEncryptedLocalDeviceKey(options.scope, credentialId)
    : unlockEncryptedLocalDeviceKey(options.scope, credentialId);
}

async function prfInput(scope: string): Promise<AuthenticationExtensionsClientInputs> {
  return {
    prf: {
      eval: { first: await domainSalt(`${DEVICE_KEY_DOMAIN}:PRF:${scope}`) },
    },
  } as AuthenticationExtensionsClientInputs & PrfInput;
}

function readPrfResult(credential: PublicKeyCredential): Uint8Array<ArrayBuffer> | undefined {
  const output = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & PrfOutput;
  const first = output.prf?.results?.first;
  return first ? new Uint8Array(first) : undefined;
}

async function deviceFromPrf(
  prf: Uint8Array<ArrayBuffer>,
  scope: string,
): Promise<DeviceKey> {
  // PRF output is credential-bound key material. Domain-separate it once more
  // before interpreting it as a secp256k1 scalar.
  for (let counter = 0; counter < 256; counter++) {
    const input = new Uint8Array(concatBytes([
      stringToBytes(`${DEVICE_KEY_DOMAIN}:SECP256K1:${scope}:`),
      prf,
      new Uint8Array([counter]),
    ]));
    const digest = new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      input,
    ));
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

async function createEncryptedLocalDeviceKey(scope: string, credentialId: string): Promise<DeviceKey> {
  assertFallbackStorageSupport();
  const storageKey = localDeviceStorageKey(scope, credentialId);
  const privateKey = generatePrivateKey();
  const privateKeyBytes = new Uint8Array(hexToBytes(privateKey));
  const wrappingKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const iv = randomBytes(12);

  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: localDeviceContext(scope, credentialId) },
      wrappingKey,
      privateKeyBytes,
    );
    await putWrappingKey(storageKey, wrappingKey);
    const record: EncryptedLocalDeviceKey = {
      version: 1,
      iv: base64Url(iv),
      ciphertext: base64Url(new Uint8Array(ciphertext)),
    };
    localStorage.setItem(storageKey, JSON.stringify(record));
    const account = privateKeyToAccount(privateKey);
    return { address: account.address, account, protection: "local-encrypted" };
  } catch (error) {
    await deleteWrappingKey(storageKey).catch(() => undefined);
    throw new Error("Could not save the encrypted fallback device key in browser storage", { cause: error });
  } finally {
    privateKeyBytes.fill(0);
  }
}

async function unlockEncryptedLocalDeviceKey(scope: string, credentialId: string): Promise<DeviceKey> {
  assertFallbackStorageSupport();
  const storageKey = localDeviceStorageKey(scope, credentialId);
  const serialized = localStorage.getItem(storageKey);
  if (!serialized) {
    throw new Error(
      "This passkey does not support PRF and has no encrypted device key on this browser. Create a new passkey on this device.",
    );
  }

  let record: EncryptedLocalDeviceKey;
  try {
    record = JSON.parse(serialized) as EncryptedLocalDeviceKey;
    if (record.version !== 1 || typeof record.iv !== "string" || typeof record.ciphertext !== "string") {
      throw new Error("Unsupported encrypted key format");
    }
  } catch (error) {
    throw new Error("The encrypted fallback device key in localStorage is invalid", { cause: error });
  }

  const wrappingKey = await getWrappingKey(storageKey);
  if (!wrappingKey) {
    throw new Error("The wrapping key for this encrypted device key is missing from IndexedDB");
  }

  let privateKeyBytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    privateKeyBytes = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(record.iv),
        additionalData: localDeviceContext(scope, credentialId),
      },
      wrappingKey,
      fromBase64Url(record.ciphertext),
    ));
    if (privateKeyBytes.length !== 32) throw new Error("Invalid private key length");
    const account = privateKeyToAccount(bytesToHex(privateKeyBytes) as Hex);
    return { address: account.address, account, protection: "local-encrypted" };
  } catch (error) {
    throw new Error("Could not decrypt the fallback device key", { cause: error });
  } finally {
    privateKeyBytes?.fill(0);
  }
}

function localDeviceStorageKey(scope: string, credentialId: string): string {
  return `${LOCAL_KEY_PREFIX}:${encodeURIComponent(scope)}:${credentialId}`;
}

function localDeviceContext(scope: string, credentialId: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(stringToBytes(`${DEVICE_KEY_DOMAIN}:LOCAL:${scope}:${credentialId}`));
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function openLocalKeyDatabase(): Promise<IDBDatabase> {
  if (!window.indexedDB) return Promise.reject(new Error("IndexedDB is unavailable"));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(LOCAL_KEY_DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(LOCAL_KEY_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open IndexedDB"));
  });
}

async function putWrappingKey(storageKey: string, wrappingKey: CryptoKey): Promise<void> {
  const database = await openLocalKeyDatabase();
  try {
    await completeTransaction(database, "readwrite", (store) => store.put(wrappingKey, storageKey));
  } finally {
    database.close();
  }
}

async function getWrappingKey(storageKey: string): Promise<CryptoKey | undefined> {
  const database = await openLocalKeyDatabase();
  try {
    return await completeTransaction<CryptoKey | undefined>(database, "readonly", (store) => store.get(storageKey));
  } finally {
    database.close();
  }
}

async function deleteWrappingKey(storageKey: string): Promise<void> {
  const database = await openLocalKeyDatabase();
  try {
    await completeTransaction(database, "readwrite", (store) => store.delete(storageKey));
  } finally {
    database.close();
  }
}

function completeTransaction<T = void>(
  database: IDBDatabase,
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(LOCAL_KEY_STORE, mode);
    const request = operation(transaction.objectStore(LOCAL_KEY_STORE));
    transaction.oncomplete = () => resolve(request.result as T);
    transaction.onerror = () => reject(transaction.error ?? request.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction was aborted"));
  });
}

async function domainSalt(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(stringToBytes(value))));
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

function assertFallbackStorageSupport(): void {
  try {
    if (window.localStorage && window.indexedDB) return;
  } catch (error) {
    throw new Error("Browser storage is unavailable for fallback key protection", { cause: error });
  }
  throw new Error("This passkey provider requires localStorage and IndexedDB for fallback key protection");
}
