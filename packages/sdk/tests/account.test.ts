import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createPasskeyDeviceKey, unlockPasskeyDeviceKey } from "../src/account";

const values = new Map<string, string>();
const wrappingKeys = new Map<string, CryptoKey>();
let assertionUserHandle: ArrayBuffer | undefined;
const credentialId = Uint8Array.from([1, 2, 3, 4]).buffer;

const localStorage = {
  getItem: (key: string) => values.get(key) ?? null,
  setItem: (key: string, value: string) => values.set(key, value),
};

const database = {
  createObjectStore: () => undefined,
  close: () => undefined,
  transaction: () => {
    const transaction: Record<string, unknown> = {};
    const finish = (result?: unknown) => {
      const request = { result };
      queueMicrotask(() => (transaction.oncomplete as (() => void) | undefined)?.());
      return request;
    };
    transaction.objectStore = () => ({
      put: (value: CryptoKey, key: string) => {
        wrappingKeys.set(key, value);
        return finish();
      },
      get: (key: string) => finish(wrappingKeys.get(key)),
      delete: (key: string) => {
        wrappingKeys.delete(key);
        return finish();
      },
    });
    return transaction;
  },
};

const indexedDB = {
  open: () => {
    const request: Record<string, unknown> = { result: database };
    queueMicrotask(() => {
      (request.onupgradeneeded as (() => void) | undefined)?.();
      (request.onsuccess as (() => void) | undefined)?.();
    });
    return request;
  },
};

const assertion = {
  rawId: credentialId,
  response: { get userHandle() { return assertionUserHandle; } },
  getClientExtensionResults: () => ({}),
};

Object.defineProperty(globalThis, "crypto", { value: webcrypto });
Object.defineProperty(globalThis, "window", {
  value: { isSecureContext: true, PublicKeyCredential: class {}, localStorage, indexedDB },
});
Object.defineProperty(globalThis, "localStorage", { value: localStorage });
Object.defineProperty(globalThis, "indexedDB", { value: indexedDB });
Object.defineProperty(globalThis, "navigator", {
  value: {
    credentials: {
      create: async ({ publicKey }: PublicKeyCredentialCreationOptions) => {
        assertionUserHandle = publicKey.user.id as ArrayBuffer;
        return assertion;
      },
      get: async () => assertion,
    },
  },
});

const options = { scope: "account-test", displayName: "Account test" };
const created = await createPasskeyDeviceKey(options);
assert.equal(created.protection, "local-encrypted");
assert.equal(values.size, 1);
assert.equal(wrappingKeys.size, 1);

const serialized = [...values.values()][0];
assert.doesNotMatch(serialized, /^[a-fA-F0-9]{64}$/);
assert.deepEqual(Object.keys(JSON.parse(serialized)).sort(), ["ciphertext", "iv", "version"]);

const unlocked = await unlockPasskeyDeviceKey(options);
assert.equal(unlocked.protection, "local-encrypted");
assert.equal(unlocked.address, created.address);

console.log("account fallback tests passed");
