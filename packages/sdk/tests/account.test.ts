import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { decodeAbiParameters, hexToBytes, type Hex } from "viem";
import {
  createPasskeyDeviceKey,
  deviceIdentifier,
  loadPasskeyDeviceKey,
  signWithPasskey,
} from "../src/account";

Object.defineProperty(globalThis, "crypto", { value: webcrypto });
Object.defineProperty(globalThis, "window", {
  value: {
    isSecureContext: true,
    PublicKeyCredential: class {},
    location: { hostname: "localhost" },
  },
});

const keyPair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
  "sign",
  "verify",
]);
const spki = await webcrypto.subtle.exportKey("spki", keyPair.publicKey);
const jwk = await webcrypto.subtle.exportKey("jwk", keyPair.publicKey);
const fromBase64Url = (value: string): Hex => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return `0x${Buffer.from(normalized, "base64").toString("hex")}`;
};
const publicKeyX = fromBase64Url(jwk.x!);
const publicKeyY = fromBase64Url(jwk.y!);
const rpIdHashBytes = new Uint8Array(
  await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode("localhost")),
);
const rpIdHash = `0x${Buffer.from(rpIdHashBytes).toString("hex")}` as Hex;
const credentialId = Uint8Array.from([1, 2, 3, 4]);
const authenticatorData = new Uint8Array(37);
authenticatorData.set(rpIdHashBytes);
authenticatorData[32] = 0x05;
let creationOptions: PublicKeyCredentialCreationOptions | undefined;
let signingCancelled = false;
let assertionSignature = Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01]);

Object.defineProperty(globalThis, "navigator", {
  value: {
    credentials: {
      create: async ({ publicKey }: CredentialCreationOptions) => {
        creationOptions = publicKey;
        return {
          rawId: credentialId.buffer,
          response: {
            getPublicKey: () => spki,
            getAuthenticatorData: () => authenticatorData.buffer,
          },
        };
      },
      get: async ({ publicKey }: CredentialRequestOptions) => {
        if (signingCancelled) return null;
        const challenge = new Uint8Array(publicKey!.challenge as ArrayBuffer);
        const encodedChallenge = Buffer.from(challenge).toString("base64url");
        const clientDataJSON = new TextEncoder().encode(
          `{"type":"webauthn.get","challenge":"${encodedChallenge}","origin":"http://localhost:5173","crossOrigin":false}`,
        );
        return {
          rawId: credentialId.buffer,
          response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON.buffer,
            signature: assertionSignature.buffer,
          },
        };
      },
    },
  },
});

const device = await createPasskeyDeviceKey({ scope: "account-test", displayName: "Account test" });
assert.deepEqual(creationOptions?.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
assert.equal(device.credentialId, "0x01020304");
assert.equal(device.publicKeyX, publicKeyX);
assert.equal(device.publicKeyY, publicKeyY);
assert.equal(device.rpIdHash, rpIdHash);
assert.equal(device.rpId, "localhost");
assert.equal(device.address, deviceIdentifier(publicKeyX, publicKeyY, rpIdHash));
assert.deepEqual(loadPasskeyDeviceKey(JSON.parse(JSON.stringify(device))), device);
assert.throws(
  () => loadPasskeyDeviceKey({ ...device, publicKeyX: `0x${"00".repeat(32)}` }),
  /identifier does not match/,
);

const challenge = `0x${"ab".repeat(32)}` as Hex;
const signature = await signWithPasskey(device, challenge);
assert.equal(signature.slice(0, 4), "0x00");
const [encodedDevice] = decodeAbiParameters([{ type: "address" }], `0x${signature.slice(4, 68)}`);
assert.equal(encodedDevice, device.address);
const [r, s, challengeIndex, typeIndex, decodedAuthData, clientDataJSON] = decodeAbiParameters(
  [
    { type: "bytes32" },
    { type: "bytes32" },
    { type: "uint256" },
    { type: "uint256" },
    { type: "bytes" },
    { type: "string" },
  ],
  `0x${signature.slice(68)}`,
);
assert.equal(r, `0x${"00".repeat(31)}05`);
assert.equal(s, `0x${"00".repeat(31)}01`);
assert.equal(decodedAuthData, `0x${Buffer.from(authenticatorData).toString("hex")}`);
assert.equal(
  clientDataJSON.slice(Number(typeIndex), Number(typeIndex) + 21),
  '"type":"webauthn.get"',
);
assert.equal(
  clientDataJSON.slice(Number(challengeIndex), Number(challengeIndex) + 57),
  `"challenge":"${Buffer.from(hexToBytes(challenge)).toString("base64url")}"`,
);

assertionSignature = Uint8Array.from([0x01, 0x02]);
await assert.rejects(signWithPasskey(device, challenge), /not a DER sequence/);
signingCancelled = true;
await assert.rejects(signWithPasskey(device, challenge), /cancelled/);

console.log("account native WebAuthn tests passed");
