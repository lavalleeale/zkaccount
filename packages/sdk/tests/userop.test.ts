import assert from "node:assert/strict";
import { decodeAbiParameters, decodeFunctionData, getAddress, parseAbi, type Hex } from "viem";
import {
  addDeviceCall,
  googleSignature,
  GOOGLE_LOGIN_RACE_MESSAGE,
  GoogleLoginRaceError,
  Google4337Client,
  JsonRpcBundlerClient,
} from "../src/userop";
import { deviceIdentifier, type DeviceKey } from "../src/account";

const account = getAddress("0x1111111111111111111111111111111111111111");
const publicKeyX = `0x${"11".repeat(32)}` as Hex;
const publicKeyY = `0x${"22".repeat(32)}` as Hex;
const rpIdHash = `0x${"33".repeat(32)}` as Hex;
const testDevice: DeviceKey = {
  address: deviceIdentifier(publicKeyX, publicKeyY, rpIdHash),
  credentialId: "0x01020304",
  publicKeyX,
  publicKeyY,
  rpId: "localhost",
  rpIdHash,
};
const device = testDevice.address;
const factory = getAddress("0x3333333333333333333333333333333333333333");
const accountAbi = parseAbi([
  "function execute(address target, uint256 value, bytes data)",
  "function queueDevice(address device, bytes32 qx, bytes32 qy, string rpId)",
]);

const outer = decodeFunctionData({ abi: accountAbi, data: addDeviceCall(account, testDevice) });
assert.equal(outer.functionName, "execute");
assert.equal(outer.args[0], account);
assert.equal(outer.args[1], 0n);
const inner = decodeFunctionData({ abi: accountAbi, data: outer.args[2] });
assert.equal(inner.functionName, "queueDevice");
assert.equal(inner.args[0], device);
assert.equal(inner.args[1], publicKeyX);
assert.equal(inner.args[2], publicKeyY);
assert.equal(inner.args[3], "localhost");

const proof = {
  proof: "0x1234" as Hex,
  publicInputs: Array.from(
    { length: 9 },
    (_, index) => `0x${index.toString(16).padStart(64, "0")}` as Hex,
  ),
};
const signature = googleSignature(proof, testDevice);
assert.equal(signature.slice(0, 4), "0x01");
const [decodedProof, decodedInputs, decodedX, decodedY, decodedRpId] = decodeAbiParameters(
  [
    { type: "bytes" },
    { type: "bytes32[]" },
    { type: "bytes32" },
    { type: "bytes32" },
    { type: "string" },
  ],
  `0x${signature.slice(4)}`,
);
assert.equal(decodedProof, proof.proof);
assert.deepEqual(decodedInputs, proof.publicInputs);
assert.equal(decodedX, publicKeyX);
assert.equal(decodedY, publicKeyY);
assert.equal(decodedRpId, "localhost");
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
    field(1n),
  ],
};
function authorizationClient(options: {
  nonces: bigint[];
  authorized: boolean[];
}): Google4337Client {
  let nonceRead = 0;
  let authorizationRead = 0;
  return Object.assign(Object.create(Google4337Client.prototype), {
    factory,
    chain: { id: 84_532, name: "Base Sepolia" },
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

const originalFetch = globalThis.fetch;
try {
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: {
          slow: { maxFeePerGas: "0x10", maxPriorityFeePerGas: "0x01" },
          standard: { maxFeePerGas: "0x20", maxPriorityFeePerGas: "0x02" },
          fast: { maxFeePerGas: "0x30", maxPriorityFeePerGas: "0x03" },
        },
      }),
      { headers: { "content-type": "application/json" } },
    );
  assert.deepEqual(
    (await new JsonRpcBundlerClient("https://bundler.example").getUserOperationGasPrice())
      ?.standard,
    { maxFeePerGas: "0x20", maxPriorityFeePerGas: "0x02" },
  );

  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32601, message: "Method not found" },
      }),
      { headers: { "content-type": "application/json" } },
    );
  assert.equal(
    await new JsonRpcBundlerClient("https://bundler.example").getUserOperationGasPrice(),
    undefined,
  );
} finally {
  globalThis.fetch = originalFetch;
}

process.stdout.write("UserOperation encoding tests passed\n");
