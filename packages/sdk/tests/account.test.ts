import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createPasskeyDeviceKey, unlockPasskeyDeviceKey } from "../src/account";

let assertionUserHandle: ArrayBuffer | undefined;
const credentialId = Uint8Array.from([1, 2, 3, 4]).buffer;

const assertion = {
  rawId: credentialId,
  response: {
    get userHandle() {
      return assertionUserHandle;
    },
  },
  getClientExtensionResults: () => ({}),
};

Object.defineProperty(globalThis, "crypto", { value: webcrypto });
Object.defineProperty(globalThis, "window", {
  value: { isSecureContext: true, PublicKeyCredential: class {} },
});
Object.defineProperty(globalThis, "navigator", {
  value: {
    credentials: {
      create: async ({ publicKey }: CredentialCreationOptions) => {
        if (!publicKey) throw new Error("Expected public-key credential creation options");
        assertionUserHandle = publicKey.user.id as ArrayBuffer;
        return assertion;
      },
      get: async () => assertion,
    },
  },
});

const options = { scope: "account-test", displayName: "Account test" };
const created = await createPasskeyDeviceKey(options);
assert.equal(created.protection, "memory-only");

const unlocked = await unlockPasskeyDeviceKey(options);
assert.equal(unlocked.protection, "memory-only");
assert.notEqual(unlocked.address, created.address);

console.log("account memory-only fallback tests passed");
