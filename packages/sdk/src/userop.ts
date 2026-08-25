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
  type Address,
  type Hex,
} from "viem";
import { baseSepolia } from "viem/chains";
import type { DeviceKey } from "./account";
import type { GoogleProof } from "./prover";

export const BASE_SEPOLIA_CHAIN_ID = 84_532;
export const ENTRY_POINT_V08 = getAddress("0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108");

const factoryAbi = parseAbi([
  "function createAccount(bytes32 identity) returns (address account)",
  "function getAddress(bytes32 identity) view returns (address)",
]);
const accountAbi = parseAbi([
  "function execute(address target, uint256 value, bytes data)",
  "function addDevice(address device)",
  "function removeDevice(address device)",
  "function addAudience(bytes32 audience)",
  "function removeAudience(bytes32 audience)",
  "function deviceKeys(address device) view returns (bool)",
  "function allowedAudiences(bytes32 audience) view returns (bool)",
]);
const entryPointAbi = [
  {
    type: "function",
    name: "getNonce",
    stateMutability: "view",
    inputs: [{ name: "sender", type: "address" }, { name: "key", type: "uint192" }],
    outputs: [{ name: "nonce", type: "uint256" }],
  },
  {
    type: "function",
    name: "getUserOpHash",
    stateMutability: "view",
    inputs: [{
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
    }],
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

export class JsonRpcBundlerClient {
  private nextId = 1;

  constructor(readonly url: string, readonly pollIntervalMs = 2_000) {}

  async supportedEntryPoints(): Promise<Address[]> {
    return (await this.request<string[]>("eth_supportedEntryPoints", [])).map(getAddress);
  }

  async estimateUserOperationGas(userOperation: UserOperationV08, entryPoint: Address = ENTRY_POINT_V08): Promise<UserOperationGasEstimate> {
    return this.request("eth_estimateUserOperationGas", [userOperation, entryPoint]);
  }

  async sendUserOperation(userOperation: UserOperationV08, entryPoint: Address = ENTRY_POINT_V08): Promise<Hex> {
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
    const body = await response.json() as JsonRpcResponse<T>;
    if (body.error) {
      const detail = body.error.data === undefined ? "" : `: ${safeStringify(body.error.data)}`;
      throw new Error(`Bundler ${method} failed (${body.error.code}): ${body.error.message}${detail}`);
    }
    if (body.result === undefined) throw new Error(`Bundler ${method} returned no result`);
    return body.result;
  }
}

export interface Google4337ClientOptions {
  factory: Address;
  bundlerUrl: string;
  rpcUrl?: string;
  entryPoint?: Address;
}

export interface SubmissionResult {
  accountAddress: Address;
  userOpHash?: Hex;
  receipt?: UserOperationReceipt;
  alreadyAuthorized?: boolean;
}

export type StatusCallback = (status: string) => void;

export class Google4337Client {
  readonly factory: Address;
  readonly entryPoint: Address;
  readonly bundler: JsonRpcBundlerClient;
  readonly publicClient;

  constructor(options: Google4337ClientOptions) {
    this.factory = getAddress(options.factory);
    this.entryPoint = getAddress(options.entryPoint ?? ENTRY_POINT_V08);
    this.bundler = new JsonRpcBundlerClient(options.bundlerUrl);
    this.publicClient = createPublicClient({
      chain: baseSepolia,
      transport: http(options.rpcUrl ?? "https://sepolia.base.org"),
    });
  }

  async assertBundlerCompatibility(): Promise<void> {
    const supported = await this.bundler.supportedEntryPoints();
    if (!supported.some((address) => isAddressEqual(address, this.entryPoint))) {
      throw new Error(`Bundler does not support EntryPoint ${this.entryPoint}`);
    }
  }

  async getAccountAddress(identity: Hex): Promise<Address> {
    return getAddress(await this.publicClient.readContract({
      address: this.factory,
      abi: factoryAbi,
      functionName: "getAddress",
      args: [identity],
    }));
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

  async getBalance(account: Address): Promise<bigint> {
    return this.publicClient.getBalance({ address: account });
  }

  async isAudienceAllowed(account: Address, clientId: string): Promise<boolean> {
    if (!(await this.isDeployed(account))) return false;
    return this.publicClient.readContract({
      address: account,
      abi: accountAbi,
      functionName: "allowedAudiences",
      args: [await hashGoogleAudience(clientId)],
    });
  }

  async authorizeDevice(proof: GoogleProof, device: DeviceKey, onStatus: StatusCallback = () => undefined): Promise<SubmissionResult> {
    validateProofContext(proof, device.address, this.factory);
    const accountAddress = await this.getAccountAddress(proof.publicInputs[0]);
    onStatus(`Smart account predicted: ${accountAddress}`);
    if (await this.isDeviceAuthorized(accountAddress, device.address)) {
      return { accountAddress, alreadyAuthorized: true };
    }
    if (await this.getBalance(accountAddress) === 0n) {
      throw new Error(`Fund counterfactual account ${accountAddress} with Base Sepolia ETH, then retry authorization`);
    }
    onStatus("Checking bundler compatibility");
    await this.assertBundlerCompatibility();
    onStatus("Creating bootstrap UserOperation");
    let operation = await this.baseOperation(accountAddress, googleSignature(proof));
    if (!(await this.isDeployed(accountAddress))) {
      operation.factory = this.factory;
      operation.factoryData = encodeFunctionData({ abi: factoryAbi, functionName: "createAccount", args: [proof.publicInputs[0]] });
    }
    operation.callData = addDeviceCall(accountAddress, device.address);
    onStatus("Estimating UserOperation gas");
    operation = await this.withGasEstimate(operation);
    onStatus("Submitting UserOperation to bundler");
    const userOpHash = await this.bundler.sendUserOperation(operation, this.entryPoint);
    onStatus(`UserOperation submitted: ${userOpHash}`);
    const receipt = await this.bundler.waitForUserOperationReceipt(userOpHash);
    if (!receipt.success) throw new Error(`Bootstrap UserOperation reverted: ${receipt.receipt.transactionHash}`);
    onStatus(`Confirmed: ${receipt.receipt.transactionHash}`);
    return { accountAddress, userOpHash, receipt };
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
    let operation = await this.baseOperation(accountAddress, dummyDeviceSignature());
    operation.callData = encodeFunctionData({
      abi: accountAbi,
      functionName: "execute",
      args: [transaction.to, transaction.value ?? 0n, transaction.data ?? "0x"],
    });
    onStatus("Estimating UserOperation gas");
    operation = await this.withGasEstimate(operation);
    const hash = await this.getUserOperationHash(operation);
    operation.signature = concat(["0x00", await device.account.sign({ hash })]);
    onStatus("Submitting device-signed UserOperation");
    const userOpHash = await this.bundler.sendUserOperation(operation, this.entryPoint);
    const receipt = await this.bundler.waitForUserOperationReceipt(userOpHash);
    if (!receipt.success) throw new Error(`UserOperation reverted: ${receipt.receipt.transactionHash}`);
    onStatus(`Confirmed: ${receipt.receipt.transactionHash}`);
    return { accountAddress, userOpHash, receipt };
  }

  async addAudience(accountAddress: Address, device: DeviceKey, clientId: string, onStatus?: StatusCallback): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "addAudience",
      args: [await hashGoogleAudience(clientId)],
    });
    return this.sendTransaction(accountAddress, device, { to: accountAddress, data }, onStatus);
  }

  async removeAudience(accountAddress: Address, device: DeviceKey, clientId: string, onStatus?: StatusCallback): Promise<SubmissionResult> {
    const data = encodeFunctionData({
      abi: accountAbi,
      functionName: "removeAudience",
      args: [await hashGoogleAudience(clientId)],
    });
    return this.sendTransaction(accountAddress, device, { to: accountAddress, data }, onStatus);
  }

  async removeDevice(accountAddress: Address, authorizingDevice: DeviceKey, deviceToRemove: Address, onStatus?: StatusCallback): Promise<SubmissionResult> {
    const data = encodeFunctionData({ abi: accountAbi, functionName: "removeDevice", args: [deviceToRemove] });
    return this.sendTransaction(accountAddress, authorizingDevice, { to: accountAddress, data }, onStatus);
  }

  private async baseOperation(sender: Address, signature: Hex): Promise<UserOperationV08> {
    const nonce = await this.publicClient.readContract({
      address: this.entryPoint,
      abi: entryPointAbi,
      functionName: "getNonce",
      args: [sender, 0n],
    });
    const estimatedFees = await this.publicClient.estimateFeesPerGas();
    const priorityFee = estimatedFees.maxPriorityFeePerGas ?? 1_000_000n;
    const estimatedMaxFee = estimatedFees.maxFeePerGas ?? await this.publicClient.getGasPrice();
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
      callGasLimit: bufferedQuantity(estimate.callGasLimit),
      verificationGasLimit: bufferedQuantity(estimate.verificationGasLimit),
      preVerificationGas: bufferedQuantity(estimate.preVerificationGas),
    };
  }

  private async getUserOperationHash(operation: UserOperationV08): Promise<Hex> {
    const initCode = operation.factory && operation.factoryData ? concat([operation.factory, operation.factoryData]) : "0x";
    return this.publicClient.readContract({
      address: this.entryPoint,
      abi: entryPointAbi,
      functionName: "getUserOpHash",
      args: [{
        sender: operation.sender,
        nonce: hexToBigInt(operation.nonce),
        initCode,
        callData: operation.callData,
        accountGasLimits: pack128(operation.verificationGasLimit, operation.callGasLimit),
        preVerificationGas: hexToBigInt(operation.preVerificationGas),
        gasFees: pack128(operation.maxPriorityFeePerGas, operation.maxFeePerGas),
        paymasterAndData: "0x",
        signature: operation.signature,
      }],
    });
  }
}

export function addDeviceCall(account: Address, device: Address): Hex {
  const inner = encodeFunctionData({ abi: accountAbi, functionName: "addDevice", args: [device] });
  return encodeFunctionData({ abi: accountAbi, functionName: "execute", args: [account, 0n, inner] });
}

export function googleSignature(proof: GoogleProof): Hex {
  const encoded = encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes32[]" }],
    [proof.proof, [...proof.publicInputs]],
  );
  return concat(["0x01", encoded]);
}

export async function hashGoogleAudience(clientId: string): Promise<Hex> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(clientId)));
  digest[0] = 0;
  return `0x${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function dummyDeviceSignature(): Hex {
  return `0x00${"00".repeat(65)}`;
}

function validateProofContext(proof: GoogleProof, device: Address, factory: Address): void {
  if (proof.publicInputs.length !== 7) throw new Error("Google proof must contain exactly seven public inputs");
  const proofDevice = getAddress(`0x${proof.publicInputs[2].slice(-40)}`);
  const proofFactory = getAddress(`0x${proof.publicInputs[4].slice(-40)}`);
  if (!isAddressEqual(proofDevice, device)) throw new Error("Google proof is bound to a different device");
  if (!isAddressEqual(proofFactory, factory)) throw new Error("Google proof is bound to a different factory");
  if (hexToBigInt(proof.publicInputs[3]) !== BigInt(BASE_SEPOLIA_CHAIN_ID)) throw new Error("Google proof is bound to a different chain");
}

function pack128(high: Hex, low: Hex): Hex {
  const highValue = hexToBigInt(high);
  const lowValue = hexToBigInt(low);
  if (highValue >= 1n << 128n || lowValue >= 1n << 128n) throw new Error("Packed gas value exceeds uint128");
  return numberToHex((highValue << 128n) | lowValue, { size: 32 });
}

function quantity(value: bigint): Hex { return numberToHex(value); }
function bufferedQuantity(value: Hex): Hex { return quantity((hexToBigInt(value) * 120n + 99n) / 100n); }
function safeStringify(value: unknown): string {
  try { return JSON.stringify(value); } catch { return String(value); }
}
