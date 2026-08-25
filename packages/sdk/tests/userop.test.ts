import assert from "node:assert/strict";
import { decodeAbiParameters, decodeFunctionData, getAddress, parseAbi, type Hex } from "viem";
import {
  addAudienceCall,
  addDeviceCall,
  googleSignature,
  GOOGLE_LOGIN_RACE_MESSAGE,
  GoogleLoginRaceError,
  Google4337Client,
  hashGoogleAudience,
  reduceAuthorizedClientIds,
  removeAudienceCall,
} from "../src/userop";
import type { DeviceKey } from "../src/account";

const account = getAddress("0x1111111111111111111111111111111111111111");
const device = getAddress("0x2222222222222222222222222222222222222222");
const factory = getAddress("0x3333333333333333333333333333333333333333");
const accountAbi = parseAbi([
  "function execute(address target, uint256 value, bytes data)",
  "function addDevice(address device)",
  "function addAudience(string clientId)",
  "function removeAudience(string clientId)",
]);

const outer = decodeFunctionData({ abi: accountAbi, data: addDeviceCall(account, device) });
assert.equal(outer.functionName, "execute");
assert.equal(outer.args[0], account);
assert.equal(outer.args[1], 0n);
const inner = decodeFunctionData({ abi: accountAbi, data: outer.args[2] });
assert.equal(inner.functionName, "addDevice");
assert.equal(inner.args[0], device);

const clientId = "demo.apps.googleusercontent.com";
const addAudience = decodeFunctionData({ abi: accountAbi, data: addAudienceCall(clientId) });
assert.equal(addAudience.functionName, "addAudience");
assert.equal(addAudience.args[0], clientId);
const removeAudience = decodeFunctionData({ abi: accountAbi, data: removeAudienceCall(clientId) });
assert.equal(removeAudience.functionName, "removeAudience");
assert.equal(removeAudience.args[0], clientId);

const firstAudience = await hashGoogleAudience("first.apps.googleusercontent.com");
const secondAudience = await hashGoogleAudience("second.apps.googleusercontent.com");
assert.deepEqual(
  reduceAuthorizedClientIds([
    { audienceHash: firstAudience, clientId: "first.apps.googleusercontent.com", enabled: true },
    { audienceHash: secondAudience, clientId: "second.apps.googleusercontent.com", enabled: true },
    { audienceHash: firstAudience, clientId: "first.apps.googleusercontent.com", enabled: false },
  ]),
  [{ audienceHash: secondAudience, clientId: "second.apps.googleusercontent.com" }],
);

const proof = {
  proof: "0x1234" as Hex,
  publicInputs: Array.from(
    { length: 8 },
    (_, index) => `0x${index.toString(16).padStart(64, "0")}` as Hex,
  ),
};
const signature = googleSignature(proof);
assert.equal(signature.slice(0, 4), "0x01");
const [decodedProof, decodedInputs] = decodeAbiParameters(
  [{ type: "bytes" }, { type: "bytes32[]" }],
  `0x${signature.slice(4)}`,
);
assert.equal(decodedProof, proof.proof);
assert.deepEqual(decodedInputs, proof.publicInputs);
const raceError = new GoogleLoginRaceError();
assert.equal(raceError.name, "GoogleLoginRaceError");
assert.equal(raceError.message, GOOGLE_LOGIN_RACE_MESSAGE);
assert.equal(
  raceError.message,
  "Another Google login completed first. Sign in with Google again to generate a fresh authorization.",
);

const field = (value: bigint): Hex => `0x${value.toString(16).padStart(64, "0")}`;
const authorizationProof = {
  proof: "0x1234" as Hex,
  publicInputs: [
    field(1n),
    field(2n),
    field(BigInt(device)),
    field(84_532n),
    field(BigInt(factory)),
    field(2_000_000_000n),
    field(3n),
    field(100n),
  ],
};
const testDevice = { address: device } as DeviceKey;

function authorizationClient(options: {
  nonces: bigint[];
  authorized: boolean[];
}): Google4337Client {
  let nonceRead = 0;
  let authorizationRead = 0;
  return Object.assign(Object.create(Google4337Client.prototype), {
    factory,
    getAccountAddress: async () => account,
    isDeviceAuthorized: async () =>
      options.authorized[Math.min(authorizationRead++, options.authorized.length - 1)],
    getGoogleNonce: async () => options.nonces[Math.min(nonceRead++, options.nonces.length - 1)],
    getBalance: async () => 1n,
    assertBundlerCompatibility: async () => {
      throw new Error("simulated bundler race");
    },
  }) as Google4337Client;
}

await assert.rejects(
  authorizationClient({ nonces: [100n], authorized: [false] }).authorizeDevice(
    authorizationProof,
    testDevice,
  ),
  (error: unknown) =>
    error instanceof GoogleLoginRaceError && error.message === GOOGLE_LOGIN_RACE_MESSAGE,
);
await assert.rejects(
  authorizationClient({ nonces: [99n, 100n], authorized: [false, false] }).authorizeDevice(
    authorizationProof,
    testDevice,
  ),
  (error: unknown) =>
    error instanceof GoogleLoginRaceError && error.message === GOOGLE_LOGIN_RACE_MESSAGE,
);
assert.deepEqual(
  await authorizationClient({ nonces: [99n], authorized: [false, true] }).authorizeDevice(
    authorizationProof,
    testDevice,
  ),
  { accountAddress: account, alreadyAuthorized: true },
);
assert.equal(
  await hashGoogleAudience(
    "176685232849-e7govufghrlnprcc7cuijp5eusopci5b.apps.googleusercontent.com",
  ),
  "0x003058e40c036af1aab38e49c89e0ee26d4d7be8fd6a665f8b37bde5507223d9",
);

process.stdout.write("UserOperation encoding tests passed\n");
