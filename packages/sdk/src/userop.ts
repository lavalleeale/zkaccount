import {
  concat,
  createPublicClient,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hexToBigInt,
  http,
  isAddressEqual,
  numberToHex,
  parseAbi,
  type Chain,
  type Address,
  type Hex,
} from "viem";
import { baseSepolia } from "viem/chains";
import { signWithPasskey, type DeviceKey, type PublicDeviceKey } from "./account";
import { GOOGLE_ACTION_ADD_DEVICE } from "./google";
import type { GoogleProof } from "./prover";

export const BASE_SEPOLIA_CHAIN_ID = 84_532;
export const ENTRY_POINT_V08 = getAddress("0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108");
export const BASE_SEPOLIA_FACTORY_DEPLOYMENT_BLOCK = 45_976_355n;
export const LOG_QUERY_BLOCK_RANGE = 5_000n;
export const LOG_QUERY_CONCURRENCY = 8;

const factoryAbi = parseAbi([
  "function createAccount(bytes32 identity) returns (address account)",
  "function getAddress(bytes32 identity) view returns (address)",
  "event AccountCreated(bytes32 indexed identity, address indexed account)",
]);
const accountAbi = parseAbi([
  "function execute(address target, uint256 value, bytes data)",
  "function addDevice(address device, bytes32 qx, bytes32 qy, string rpId)",
  "function queueDevice(address device, bytes32 qx, bytes32 qy, string rpId)",
  "function approveDevice(address device)",
  "function cancelPendingDevice(address device)",
  "function removeDevice(address device)",
  "function removeAllDevices(address[] devices)",
  "function deviceKeys(address device) view returns (bool)",
  "function pendingDevices(address device) view returns (bytes32 qx, bytes32 qy, bytes32 rpIdHash, uint48 queuedAt, string rpId)",
  "function DEVICE_ADD_DELAY() view returns (uint48)",
  "function googleNonce() view returns (uint64)",
  "event DeviceSet(address indexed device, bool enabled, string rpId)",
  "event DeviceQueued(address indexed device, string rpId, uint48 readyAt)",
]);
const entryPointAbi = [
  {
    type: "function",
    name: "getNonce",
    stateMutability: "view",
    inputs: [
      { name: "sender", type: "address" },
      { name: "key", type: "uint192" },
    ],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
  {
    type: "function",
    name: "getUserOpHash",
    stateMutability: "view",
    inputs: [
      {
        name: "userOp",
        type: "tuple",
        components: [
          { name: "sender", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "initCode", type: "bytes" },
          { name: "callData", type: "bytes" },
          { name: "accountGasLimits", type: "bytes32" },
          { name: "preVerificationGas", type: "uint256" },
          { name: "gasFees", type: "bytes32" },
          { name: "paymasterAndData", type: "bytes" },
          { name: "signature", type: "bytes" },
        ],
      },
    ],
    outputs: [{ name: "", type: "bytes32" }],
  },
] as const;

export interface UserOperationV08 {
  sender: Address;
  nonce: Hex;
  factory?: Address;
  factoryData?: Hex;
  callData: Hex;
  callGasLimit: Hex;
  verificationGasLimit: Hex;
  preVerificationGas: Hex;
  maxPriorityFeePerGas: Hex;
  maxFeePerGas: Hex;
  signature: Hex;
}

export interface UserOperationGasEstimate {
  callGasLimit: Hex;
  verificationGasLimit: Hex;
  preVerificationGas: Hex;
}

export interface UserOperationGasPriceTier {
  maxFeePerGas: Hex;
  maxPriorityFeePerGas: Hex;
}

export interface UserOperationGasPrices {
  slow: UserOperationGasPriceTier;
  standard: UserOperationGasPriceTier;
  fast: UserOperationGasPriceTier;
}

export interface UserOperationReceipt {
  userOpHash: Hex;
  sender: Address;
  nonce: Hex;
  success: boolean;
  actualGasCost?: Hex;
  actualGasUsed?: Hex;
  receipt: { transactionHash: Hex; blockNumber?: Hex; status?: Hex };
}

interface JsonRpcResponse<T> {
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

class BundlerJsonRpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = "BundlerJsonRpcError";
  }
}

export class JsonRpcBundlerClient {
  private nextId = 1;

  constructor(
    readonly url: string,
    readonly pollIntervalMs = 2_000,
  ) {}

  async supportedEntryPoints(): Promise<Address[]> {
    return (await this.request<string[]>("eth_supportedEntryPoints", [])).map(getAddress);
  }

  async getUserOperationGasPrice(): Promise<UserOperationGasPrices | undefined> {
    try {
      return await this.request("pimlico_getUserOperationGasPrice", []);
    } catch (error) {
      if (error instanceof BundlerJsonRpcError && error.code === -32601) return undefined;
      throw error;
    }
  }

  async estimateUserOperationGas(
    userOperation: UserOperationV08,
    entryPoint: Address = ENTRY_POINT_V08,
  ): Promise<UserOperationGasEstimate> {
    return this.request("eth_estimateUserOperationGas", [userOperation, entryPoint]);
  }

  async sendUserOperation(
    userOperation: UserOperationV08,
    entryPoint: Address = ENTRY_POINT_V08,
  ): Promise<Hex> {
    return this.request("eth_sendUserOperation", [userOperation, entryPoint]);
  }

  async getUserOperationReceipt(hash: Hex): Promise<UserOperationReceipt | null> {
    return this.request("eth_getUserOperationReceipt", [hash]);
  }

  async waitForUserOperationReceipt(hash: Hex, timeoutMs = 120_000): Promise<UserOperationReceipt> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const receipt = await this.getUserOperationReceipt(hash);
      if (receipt) return receipt;
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs));
    }
    throw new Error(`Timed out waiting for UserOperation ${hash}`);
  }

  private async request<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: this.nextId++, method, params }),
    });
    if (!response.ok) throw new Error(`Bundler HTTP ${response.status}: ${await response.text()}`);
    const body = (await response.json()) as JsonRpcResponse<T>;
    if (body.error) {
      const detail = body.error.data === undefined ? "" : `: ${safeStringify(body.error.data)}`;
      throw new BundlerJsonRpcError(
        body.error.code,
        `Bundler ${method} failed (${body.error.code}): ${body.error.message}${detail}`,
      );
    }
    if (body.result === undefined) throw new Error(`Bundler ${method} returned no result`);
    return body.result;
  }
}

export interface Google4337ClientOptions {
  factory: Address;
  bundlerUrl: string;
  rpcUrl?: string;
  chain?: Chain;
  entryPoint?: Address;
  factoryDeploymentBlock?: bigint;
}

export interface AuthorizedDevice extends PublicDeviceKey {
  enabled: boolean;
}

export interface PendingDevice {
  readyAt: number;
}

export interface PendingDeviceInfo {
  address: Address;
  rpId: string;
  readyAt: number;
}

export interface SubmissionResult {
  accountAddress: Address;
  userOpHash?: Hex;
  receipt?: UserOperationReceipt;
  alreadyAuthorized?: boolean;
  /** Set when a Google-authorized device was queued behind the account's
   * timelock instead of activating immediately (see `GoogleAccount.queueDevice`). */
  pending?: PendingDevice;
}

export type StatusCallback = (status: string) => void;

export const GOOGLE_LOGIN_RACE_MESSAGE =
  "Another Google login completed first. Sign in with Google again to generate a fresh authorization.";

export class GoogleLoginRaceError extends Error {
  constructor() {
    super(GOOGLE_LOGIN_RACE_MESSAGE);
    this.name = "GoogleLoginRaceError";
  }
}

interface DeviceSetLogEntry {
  device: Address;
  enabled: boolean;
  rpId: string;
}

interface DeviceQueuedLogEntry {
  device: Address;
  rpId: string;
}

interface AccountEventCacheEntry<T> {
  toBlock: bigint;
  events: T[];
}

export class Google4337Client {
  readonly chain: Chain;
  readonly factory: Address;
  readonly entryPoint: Address;
  readonly factoryDeploymentBlock: bigint;
  readonly bundler: JsonRpcBundlerClient;
  readonly publicClient;

  // Populated lazily from the factory's AccountCreated event and kept for the
  // client's lifetime: an account's deployment block never changes, so this
  // lets device-event scans start from it instead of factoryDeploymentBlock.
  private readonly deploymentBlockCache = new Map<Address, bigint>();
  // Device-event scans are incremental: each cache entry remembers the last
  // block scanned and the events accumulated so far, so a repeated call only
  // queries the blocks added since the previous call instead of re-scanning
  // the account's entire history every time.
  private readonly deviceSetCache = new Map<Address, AccountEventCacheEntry<DeviceSetLogEntry>>();
  private readonly deviceQueuedCache = new Map<
    Address,
    AccountEventCacheEntry<DeviceQueuedLogEntry>
  >();

  constructor(options: Google4337ClientOptions) {
    this.chain = options.chain ?? baseSepolia;
    this.factory = getAddress(options.factory);
    this.entryPoint = getAddress(options.entryPoint ?? ENTRY_POINT_V08);
    this.factoryDeploymentBlock =
      options.factoryDeploymentBlock ?? BASE_SEPOLIA_FACTORY_DEPLOYMENT_BLOCK;
    this.bundler = new JsonRpcBundlerClient(options.bundlerUrl);
    this.publicClient = createPublicClient({
      chain: this.chain,
      transport: http(options.rpcUrl ?? this.chain.rpcUrls.default.http[0]),
    });
  }

  async assertBundlerCompatibility(): Promise<void> {
    const supported = await this.bundler.supportedEntryPoints();
    if (!supported.some((address) => isAddressEqual(address, this.entryPoint))) {
      throw new Error(`Bundler does not support EntryPoint ${this.entryPoint}`);
    }
  }

  async getAccountAddress(identity: Hex): Promise<Address> {
    return getAddress(
      await this.publicClient.readContract({
        address: this.factory,
        abi: factoryAbi,
        functionName: "getAddress",
        args: [identity],
      }),
    );
  }

  async isDeployed(account: Address): Promise<boolean> {
    return (await this.publicClient.getCode({ address: account })) !== undefined;
  }

  async isDeviceAuthorized(account: Address, device: Address): Promise<boolean> {
    if (!(await this.isDeployed(account))) return false;
    return this.publicClient.readContract({
      address: account,
      abi: accountAbi,
      functionName: "deviceKeys",
      args: [device],
    });
  }

  async getPendingDevice(account: Address, device: Address): Promise<PendingDevice | undefined> {
    if (!(await this.isDeployed(account))) return undefined;
    const [, , , queuedAt] = await this.publicClient.readContract({
      address: account,
      abi: accountAbi,
      functionName: "pendingDevices",
      args: [device],
    });
    if (queuedAt === 0) return undefined;
    const delay = await this.publicClient.readContract({
      address: account,
      abi: accountAbi,
      functionName: "DEVICE_ADD_DELAY",
    });
    return { readyAt: queuedAt + delay };
  }

  async getGoogleNonce(account: Address): Promise<bigint> {
    if (!(await this.isDeployed(account))) return 0n;
    return this.publicClient.readContract({
      address: account,
      abi: accountAbi,
      functionName: "googleNonce",
    });
  }

  async getBalance(account: Address): Promise<bigint> {
    return this.publicClient.getBalance({ address: account });
  }

  async listAuthorizedDevices(account: Address): Promise<AuthorizedDevice[]> {
    if (!(await this.isDeployed(account))) return [];
    const events = await this.scanAccountEvents(
      account,
      "DeviceSet",
      this.deviceSetCache,
      (args) => ({ device: args.device, enabled: args.enabled, rpId: args.rpId }),
    );
    return reduceAuthorizedDevices(events);
  }

  /// Lists devices queued behind the account's timelock (Google-authorized
  /// but not yet active), re-checking each against current on-chain state so
  /// devices that have since been approved or cancelled are excluded.
  async listPendingDevices(account: Address): Promise<PendingDeviceInfo[]> {
    if (!(await this.isDeployed(account))) return [];
    const events = await this.scanAccountEvents(
      account,
      "DeviceQueued",
      this.deviceQueuedCache,
      (args) => ({ device: args.device, rpId: args.rpId }),
    );
    const seen = new Map<Address, string>();
    for (const event of events) seen.set(event.device, event.rpId);
    const pending = await Promise.all(
      [...seen.entries()].map(async ([device, rpId]) => {
        const info = await this.getPendingDevice(account, device);
        return info ? { address: device, rpId, readyAt: info.readyAt } : undefined;
      }),
    );
    return pending
      .filter((entry): entry is PendingDeviceInfo => entry !== undefined)
      .sort((left, right) => left.readyAt - right.readyAt);
  }

  /// Fetches an account's `eventName` logs, using and updating `cache` so
  /// repeated calls only query the blocks added since the previous call
  /// instead of re-scanning the account's full history every time.
  private async scanAccountEvents<T>(
    account: Address,
    eventName: "DeviceSet" | "DeviceQueued",
    cache: Map<Address, AccountEventCacheEntry<T>>,
    mapArgs: (args: { device: Address; enabled: boolean; rpId: string }) => T,
  ): Promise<T[]> {
    const latestBlock = await this.publicClient.getBlockNumber();
    const cached = cache.get(account);
    const fromBlock = cached
      ? cached.toBlock + 1n
      : await this.getDeploymentBlock(account, latestBlock);
    const events = cached ? [...cached.events] : [];
    if (fromBlock <= latestBlock) {
      const ranges = blockRangeChunks(fromBlock, latestBlock);
      const chunks = await mapWithConcurrency(ranges, LOG_QUERY_CONCURRENCY, (range) =>
        this.publicClient.getContractEvents({
          address: account,
          abi: accountAbi,
          eventName,
          fromBlock: range.fromBlock,
          toBlock: range.toBlock,
          strict: true,
        }),
      );
      for (const logs of chunks) {
        for (const log of logs) {
          events.push(mapArgs(log.args as { device: Address; enabled: boolean; rpId: string }));
        }
      }
    }
    cache.set(account, { toBlock: latestBlock, events });
    return events;
  }

  /// Resolves and caches the block the account was created in, using the
  /// factory's AccountCreated event so device-event scans for a long-lived
  /// factory start near the account's own history instead of walking every
  /// block back to the factory's own deployment.
  private async getDeploymentBlock(account: Address, latestBlock: bigint): Promise<bigint> {
    const cached = this.deploymentBlockCache.get(account);
    if (cached !== undefined) return cached;
    const ranges = blockRangeChunks(this.factoryDeploymentBlock, latestBlock);
    const chunks = await mapWithConcurrency(ranges, LOG_QUERY_CONCURRENCY, (range) =>
      this.publicClient.getContractEvents({
        address: this.factory,
        abi: factoryAbi,
        eventName: "AccountCreated",
        args: { account },
        fromBlock: range.fromBlock,
        toBlock: range.toBlock,
        strict: true,
      }),
    );
    const deploymentBlock = chunks.flat()[0]?.blockNumber ?? this.factoryDeploymentBlock;
    this.deploymentBlockCache.set(account, deploymentBlock);
    return deploymentBlock;
  }

  async authorizeDevice(
    proof: GoogleProof,
    device: PublicDeviceKey,
    onStatus: StatusCallback = () => undefined,
  ): Promise<SubmissionResult> {
    const proofGoogleNonce = validateProofContext(
      proof,
      device.address,
      this.factory,
      this.chain.id,
      GOOGLE_ACTION_ADD_DEVICE,
    );
    const accountAddress = await this.getAccountAddress(proof.publicInputs[0]);
    onStatus(`Smart account predicted: ${accountAddress}`);
    if (await this.isDeviceAuthorized(accountAddress, device.address)) {
      return { accountAddress, alreadyAuthorized: true };
    }
    if ((await this.getGoogleNonce(accountAddress)) >= proofGoogleNonce) {
      throw new GoogleLoginRaceError();
    }
    if ((await this.getBalance(accountAddress)) === 0n) {
      throw new Error(
        `Fund counterfactual account ${accountAddress} with ${this.chain.name} ETH, then retry authorization`,
      );
    }
    try {
      onStatus("Checking bundler compatibility");
      await this.assertBundlerCompatibility();
      onStatus("Creating bootstrap UserOperation");
      let operation = await this.baseOperation(accountAddress, googleSignature(proof, device));
      if (!(await this.isDeployed(accountAddress))) {
        operation.factory = this.factory;
        operation.factoryData = encodeFunctionData({
          abi: factoryAbi,
          functionName: "createAccount",
          args: [proof.publicInputs[0]],
        });
      }
      operation.callData = addDeviceCall(accountAddress, device);
      onStatus("Estimating UserOperation gas");
      operation = await this.withGasEstimate(operation);
      onStatus("Submitting UserOperation to bundler");
      const userOpHash = await this.bundler.sendUserOperation(operation, this.entryPoint);
      onStatus(`UserOperation submitted: ${userOpHash}`);
      const receipt = await this.bundler.waitForUserOperationReceipt(userOpHash);
      if (!receipt.success)
        throw new Error(`Bootstrap UserOperation reverted: ${receipt.receipt.transactionHash}`);
      onStatus(`Confirmed: ${receipt.receipt.transactionHash}`);
      if (await this.isDeviceAuthorized(accountAddress, device.address)) {
        return { accountAddress, userOpHash, receipt };
      }
      const pending = await this.getPendingDevice(accountAddress, device.address);
      if (pending) {
        onStatus(
          `Device queued behind the account's timelock, ready at ${new Date(pending.readyAt * 1000).toLocaleString()}`,
        );
        return { accountAddress, userOpHash, receipt, pending };
      }
      return { accountAddress, userOpHash, receipt };
    } catch (error) {
      if (await this.isDeviceAuthorized(accountAddress, device.address)) {
        return { accountAddress, alreadyAuthorized: true };
      }
      if ((await this.getGoogleNonce(accountAddress)) >= proofGoogleNonce) {
        throw new GoogleLoginRaceError();
      }
      throw error;
    }
  }

  async sendTransaction(
    accountAddress: Address,
    device: DeviceKey,
    transaction: { to: Address; value?: bigint; data?: Hex },
    onStatus: StatusCallback = () => undefined,
  ): Promise<SubmissionResult> {
    if (!(await this.isDeviceAuthorized(accountAddress, device.address))) {
      throw new Error(`Local device ${device.address} is not authorized by ${accountAddress}`);
    }
    onStatus("Creating device-signed UserOperation");
    let operation = await this.baseOperation(accountAddress, dummyDeviceSignature(device));
    operation.callData = encodeFunctionData({
      abi: accountAbi,
      functionName: "execute",
      args: [transaction.to, transaction.value ?? 0n, transaction.data ?? "0x"],
    });
    onStatus("Estimating UserOperation gas");
    operation = await this.withGasEstimate(operation);
    const hash = await this.getUserOperationHash(operation);
    onStatus("Confirm the UserOperation with your passkey");
    operation.signature = await signWithPasskey(device, hash);
    onStatus("Submitting passkey-signed UserOperation");
    const userOpHash = await this.bundler.sendUserOperation(operation, this.entryPoint);
    const receipt = await this.bundler.waitForUserOperationReceipt(userOpHash);
    if (!receipt.success)
      throw new Error(`UserOperation reverted: ${receipt.receipt.transactionHash}`);
    onStatus(`Confirmed: ${receipt.receipt.transactionHash}`);
    return { accountAddress, userOpHash, receipt };
  }

  async removeDevice(
    accountAddress: Address,
    authorizingDevice: DeviceKey,
    deviceToRemove: Address,
    onStatus?: StatusCallback,
  ): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "removeDevice",
      args: [deviceToRemove],
    });
    return this.sendTransaction(
      accountAddress,
      authorizingDevice,
      { to: accountAddress, data },
      onStatus,
    );
  }

  /// Lets an already-authorized local device vouch for a device still queued
  /// behind the Google-authorization timelock, activating it immediately
  /// instead of waiting out `DEVICE_ADD_DELAY`.
  async approveDevice(
    accountAddress: Address,
    authorizingDevice: DeviceKey,
    deviceToApprove: Address,
    onStatus?: StatusCallback,
  ): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "approveDevice",
      args: [deviceToApprove],
    });
    return this.sendTransaction(
      accountAddress,
      authorizingDevice,
      { to: accountAddress, data },
      onStatus,
    );
  }

  /// Vetoes a device still queued behind the Google-authorization timelock,
  /// signed by an already-authorized local device.
  async cancelPendingDevice(
    accountAddress: Address,
    authorizingDevice: DeviceKey,
    deviceToCancel: Address,
    onStatus?: StatusCallback,
  ): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "cancelPendingDevice",
      args: [deviceToCancel],
    });
    return this.sendTransaction(
      accountAddress,
      authorizingDevice,
      { to: accountAddress, data },
      onStatus,
    );
  }

  /// Revokes every given device in a single UserOperation, signed by the
  /// local passkey. Google proofs cannot authorize this call: each proof is
  /// bound to exactly one device and action.
  async removeAllDevices(
    accountAddress: Address,
    authorizingDevice: DeviceKey,
    devicesToRemove: readonly Address[],
    onStatus?: StatusCallback,
  ): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "removeAllDevices",
      args: [[...devicesToRemove]],
    });
    return this.sendTransaction(
      accountAddress,
      authorizingDevice,
      { to: accountAddress, data },
      onStatus,
    );
  }

  private async baseOperation(sender: Address, signature: Hex): Promise<UserOperationV08> {
    const nonce = await this.publicClient.readContract({
      address: this.entryPoint,
      abi: entryPointAbi,
      functionName: "getNonce",
      args: [sender, 0n],
    });
    const bundlerGasPrices = await this.bundler.getUserOperationGasPrice();
    const estimatedFees = bundlerGasPrices
      ? undefined
      : await this.publicClient.estimateFeesPerGas();
    const priorityFee = bundlerGasPrices
      ? hexToBigInt(bundlerGasPrices.standard.maxPriorityFeePerGas)
      : (estimatedFees?.maxPriorityFeePerGas ?? 1_000_000n);
    const estimatedMaxFee = bundlerGasPrices
      ? hexToBigInt(bundlerGasPrices.standard.maxFeePerGas)
      : (estimatedFees?.maxFeePerGas ?? (await this.publicClient.getGasPrice()));
    const maxFee = estimatedMaxFee > priorityFee ? estimatedMaxFee : priorityFee;
    const googleMode = signature.startsWith("0x01");
    return {
      sender,
      nonce: quantity(nonce),
      callData: "0x",
      // Non-zero provisional limits let bundlers simulate the operation before
      // returning precise values. The real proof currently requires a relaxed
      // policy bundler and substantially more validation gas than device mode.
      callGasLimit: quantity(500_000n),
      verificationGasLimit: quantity(googleMode ? 5_000_000n : 500_000n),
      preVerificationGas: quantity(500_000n),
      maxPriorityFeePerGas: quantity(priorityFee),
      maxFeePerGas: quantity(maxFee),
      signature,
    };
  }

  private async withGasEstimate(operation: UserOperationV08): Promise<UserOperationV08> {
    const estimate = await this.bundler.estimateUserOperationGas(operation, this.entryPoint);
    return {
      ...operation,
      callGasLimit: maxQuantity(operation.callGasLimit, bufferedQuantity(estimate.callGasLimit)),
      // The dummy signature used to obtain this estimate can take a cheaper
      // path through validateUserOp than a real WebAuthn assertion (e.g. it
      // may reference a device the account doesn't recognize, short-circuiting
      // before signature verification runs), so never let the estimate lower
      // the provisional floor set in baseOperation.
      verificationGasLimit: maxQuantity(
        operation.verificationGasLimit,
        bufferedQuantity(estimate.verificationGasLimit),
      ),
      preVerificationGas: maxQuantity(
        operation.preVerificationGas,
        bufferedQuantity(estimate.preVerificationGas),
      ),
    };
  }

  private async getUserOperationHash(operation: UserOperationV08): Promise<Hex> {
    const initCode =
      operation.factory && operation.factoryData
        ? concat([operation.factory, operation.factoryData])
        : "0x";
    return this.publicClient.readContract({
      address: this.entryPoint,
      abi: entryPointAbi,
      functionName: "getUserOpHash",
      args: [
        {
          sender: operation.sender,
          nonce: hexToBigInt(operation.nonce),
          initCode,
          callData: operation.callData,
          accountGasLimits: pack128(operation.verificationGasLimit, operation.callGasLimit),
          preVerificationGas: hexToBigInt(operation.preVerificationGas),
          gasFees: pack128(operation.maxPriorityFeePerGas, operation.maxFeePerGas),
          paymasterAndData: "0x",
          signature: operation.signature,
        },
      ],
    });
  }
}

/// Builds the self-call a Google-authorized proof must match: `queueDevice`,
/// not `addDevice`. `GoogleAccount` queues Google-authorized additions behind
/// a timelock (instant only when the account has no devices yet to protect);
/// an existing device can later call `approveDevice` to skip the wait.
export function addDeviceCall(account: Address, device: PublicDeviceKey): Hex {
  const inner = encodeFunctionData({
    abi: accountAbi,
    functionName: "queueDevice",
    args: [device.address, device.publicKeyX, device.publicKeyY, device.rpId],
  });
  return encodeFunctionData({
    abi: accountAbi,
    functionName: "execute",
    args: [account, 0n, inner],
  });
}

export function reduceAuthorizedDevices(
  events: ReadonlyArray<{ device: Address; enabled: boolean; rpId: string }>,
): AuthorizedDevice[] {
  const active = new Map<Address, AuthorizedDevice>();
  for (const event of events) {
    if (!event.enabled) {
      active.delete(event.device);
      continue;
    }
    active.set(event.device, {
      address: event.device,
      enabled: true,
      rpId: event.rpId,
      rpIdHash: "0x" as Hex,
      publicKeyX: "0x" as Hex,
      publicKeyY: "0x" as Hex,
    });
  }
  return [...active.values()].sort((left, right) => left.rpId.localeCompare(right.rpId));
}

export function blockRangeChunks(
  fromBlock: bigint,
  toBlock: bigint,
  rangeSize: bigint = LOG_QUERY_BLOCK_RANGE,
): Array<{ fromBlock: bigint; toBlock: bigint }> {
  if (rangeSize <= 0n) throw new Error("Log query block range must be positive");
  const ranges: Array<{ fromBlock: bigint; toBlock: bigint }> = [];
  for (let start = fromBlock; start <= toBlock; start += rangeSize) {
    const end = start + rangeSize - 1n;
    ranges.push({ fromBlock: start, toBlock: end < toBlock ? end : toBlock });
  }
  return ranges;
}

/// Runs `fn` over `items` with at most `concurrency` calls in flight at once,
/// preserving input order in the returned array.
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    for (let index = next++; index < items.length; index = next++) {
      results[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

export function googleSignature(
  proof: GoogleProof,
  device: Pick<PublicDeviceKey, "publicKeyX" | "publicKeyY" | "rpId">,
): Hex {
  const encoded = encodeAbiParameters(
    [
      { type: "bytes" },
      { type: "bytes32[]" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "string" },
    ],
    [proof.proof, [...proof.publicInputs], device.publicKeyX, device.publicKeyY, device.rpId],
  );
  return concat(["0x01", encoded]);
}

/// Builds a signature for gas estimation only, never submitted on-chain. It
/// references the real (already-authorized) device rather than the zero
/// address so `_validateWebAuthn` doesn't short-circuit on `!credential.enabled`
/// during simulation: an unrecognized device returns immediately, which used
/// to make the bundler's estimate miss the cost of the actual WebAuthn decode
/// and P-256 verification, undershooting `verificationGasLimit` for the real
/// operation and causing it to revert out of gas (AA23).
function dummyDeviceSignature(device: Pick<DeviceKey, "address" | "rpIdHash">): Hex {
  const encodedDevice = encodeAbiParameters([{ type: "address" }], [device.address]);
  const authenticatorData = concat([device.rpIdHash, "0x05", `0x${"00".repeat(4)}`]);
  const clientDataJSON =
    '{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.invalid"}';
  const typeIndex = clientDataJSON.indexOf('"type":"webauthn.get"');
  const challengeIndex = clientDataJSON.indexOf('"challenge":"');
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
      `0x${"00".repeat(31)}01`,
      `0x${"00".repeat(31)}01`,
      BigInt(challengeIndex),
      BigInt(typeIndex),
      authenticatorData,
      clientDataJSON,
    ],
  );
  return concat(["0x00", encodedDevice, encodedAssertion]);
}

function validateProofContext(
  proof: GoogleProof,
  device: Address,
  factory: Address,
  chainId: number,
  action: number,
): bigint {
  if (proof.publicInputs.length !== 9)
    throw new Error("Google proof must contain exactly nine public inputs");
  const proofDevice = getAddress(`0x${proof.publicInputs[2].slice(-40)}`);
  const proofFactory = getAddress(`0x${proof.publicInputs[4].slice(-40)}`);
  if (!isAddressEqual(proofDevice, device))
    throw new Error("Google proof is bound to a different device");
  if (!isAddressEqual(proofFactory, factory))
    throw new Error("Google proof is bound to a different factory");
  if (hexToBigInt(proof.publicInputs[3]) !== BigInt(chainId))
    throw new Error("Google proof is bound to a different chain");
  if (hexToBigInt(proof.publicInputs[8]) !== BigInt(action))
    throw new Error("Google proof is bound to a different action");
  const googleNonce = hexToBigInt(proof.publicInputs[7]);
  if (googleNonce <= 0n || googleNonce > (1n << 64n) - 1n)
    throw new Error("Google proof has an invalid issued-at nonce");
  return googleNonce;
}

function pack128(high: Hex, low: Hex): Hex {
  const highValue = hexToBigInt(high);
  const lowValue = hexToBigInt(low);
  if (highValue >= 1n << 128n || lowValue >= 1n << 128n)
    throw new Error("Packed gas value exceeds uint128");
  return numberToHex((highValue << 128n) | lowValue, { size: 32 });
}

function quantity(value: bigint): Hex {
  return numberToHex(value);
}
function bufferedQuantity(value: Hex): Hex {
  return quantity((hexToBigInt(value) * 120n + 99n) / 100n);
}
function maxQuantity(a: Hex, b: Hex): Hex {
  const left = hexToBigInt(a);
  const right = hexToBigInt(b);
  return left > right ? a : b;
}
function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
