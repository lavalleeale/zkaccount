import assert from "node:assert/strict";
import { decodeAbiParameters, decodeFunctionData, getAddress, parseAbi, type Hex } from "viem";
import {
  addDeviceCall,
  blockRangeChunks,
  googleSignature,
  GOOGLE_LOGIN_RACE_MESSAGE,
  GoogleLoginRaceError,
  Google4337Client,
  JsonRpcBundlerClient,
  mapWithConcurrency,
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
assert.deepEqual(blockRangeChunks(10_000n, 12_500n, 1_000n), [
  { fromBlock: 10_000n, toBlock: 10_999n },
  { fromBlock: 11_000n, toBlock: 11_999n },
  { fromBlock: 12_000n, toBlock: 12_500n },
]);
assert.deepEqual(blockRangeChunks(10_000n, 10_000n), [{ fromBlock: 10_000n, toBlock: 10_000n }]);
assert.deepEqual(blockRangeChunks(10_001n, 10_000n), []);
assert.throws(() => blockRangeChunks(0n, 1n, 0n), /must be positive/);
assert.deepEqual(blockRangeChunks(0n, 12_000n), [
  { fromBlock: 0n, toBlock: 4_999n },
  { fromBlock: 5_000n, toBlock: 9_999n },
  { fromBlock: 10_000n, toBlock: 12_000n },
]);

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

{
  const deviceA = device;
  const deviceB = getAddress("0x4444444444444444444444444444444444444444");
  const factoryDeploymentBlock = 100n;
  const deploymentBlock = 150n;
  let latestBlock = 200n;
  let accountCreatedCalls = 0;
  const deviceSetCalls: Array<{ fromBlock: bigint; toBlock: bigint }> = [];
  const deviceSetLogs: Array<{
    blockNumber: bigint;
    args: { device: string; enabled: boolean; rpId: string };
  }> = [{ blockNumber: 160n, args: { device: deviceA, enabled: true, rpId: "x" } }];

  const client = new Google4337Client({
    factory,
    bundlerUrl: "https://bundler.example",
    rpcUrl: "http://localhost:8646",
    factoryDeploymentBlock,
  });
  Object.assign(client.publicClient, {
    getBlockNumber: async () => latestBlock,
    getCode: async () => "0x1234",
    getContractEvents: async (options: {
      eventName: string;
      fromBlock: bigint;
      toBlock: bigint;
    }) => {
      if (options.eventName === "AccountCreated") {
        accountCreatedCalls++;
        if (deploymentBlock >= options.fromBlock && deploymentBlock <= options.toBlock) {
          return [{ blockNumber: deploymentBlock, args: { identity: "0x00", account } }];
        }
        return [];
      }
      if (options.eventName === "DeviceSet") {
        deviceSetCalls.push({ fromBlock: options.fromBlock, toBlock: options.toBlock });
        return deviceSetLogs
          .filter((log) => log.blockNumber >= options.fromBlock && log.blockNumber <= options.toBlock)
          .map((log) => ({ args: log.args }));
      }
      throw new Error(`Unexpected event query: ${options.eventName}`);
    },
  });

  const firstScan = await client.listAuthorizedDevices(account);
  assert.deepEqual(
    firstScan.map((entry) => entry.address),
    [deviceA],
  );
  assert.equal(accountCreatedCalls, 1);
  assert.deepEqual(deviceSetCalls, [{ fromBlock: deploymentBlock, toBlock: latestBlock }]);

  const previousLatestBlock = latestBlock;
  latestBlock = 250n;
  deviceSetLogs.push({ blockNumber: 220n, args: { device: deviceB, enabled: true, rpId: "y" } });
  const secondScan = await client.listAuthorizedDevices(account);
  assert.deepEqual(
    secondScan.map((entry) => entry.address).sort(),
    [deviceA, deviceB].sort(),
  );
  assert.equal(accountCreatedCalls, 1, "deployment block lookup must not repeat once cached");
  assert.deepEqual(deviceSetCalls, [
    { fromBlock: deploymentBlock, toBlock: previousLatestBlock },
    { fromBlock: previousLatestBlock + 1n, toBlock: latestBlock },
  ]);
}

{
  const order: number[] = [];
  let maxInFlight = 0;
  let inFlight = 0;
  const results = await mapWithConcurrency([1, 2, 3, 4, 5], 2, async (item) => {
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((resolve) => setTimeout(resolve, item % 2 === 0 ? 1 : 5));
    inFlight--;
    order.push(item);
    return item * 2;
  });
  assert.deepEqual(results, [2, 4, 6, 8, 10]);
  assert.ok(maxInFlight <= 2, `expected at most 2 concurrent calls, saw ${maxInFlight}`);
}

process.stdout.write("UserOperation encoding tests passed\n");
