import {
  getAddress,
  hexToBigInt,
  isAddress,
  isAddressEqual,
  isHex,
  type Address,
  type Hex,
  type PrivateKeyAccount,
} from "viem";
import type { DeviceKey, Google4337Client } from "@zkaccount/sdk";
export const WALLET_METHODS = [
  "eth_sendTransaction",
  "personal_sign",
  "eth_signTypedData_v4",
] as const;
export const WALLET_EVENTS = ["accountsChanged", "chainChanged"] as const;

export type WalletMethod = (typeof WALLET_METHODS)[number];

export interface ParsedTransaction {
  from: Address;
  to: Address;
  value: bigint;
  data: Hex;
}

export interface ParsedPersonalSign {
  account: Address;
  message: Hex;
}

interface TypedDataPayload {
  domain?: Record<string, unknown>;
  types: Record<string, readonly { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface ParsedTypedData {
  account: Address;
  typedData: TypedDataPayload;
}

export interface WalletRpcRequest {
  method: string;
  params: unknown;
}

export interface ExecuteWalletRequestOptions {
  chainId: string;
  request: WalletRpcRequest;
  account: Address;
  device: DeviceKey;
  wallet: Google4337Client;
  onStatus?: (status: string) => void;
}

export function parseTransaction(params: unknown, account: Address): ParsedTransaction {
  const value = firstObject(params, "Transaction parameters");
  if (typeof value.from !== "string" || !isAddress(value.from)) {
    throw new Error("Transaction from must be a valid address");
  }
  if (!isAddressEqual(value.from, account)) {
    throw new Error(`Transaction from must be the active smart account ${account}`);
  }
  if (typeof value.to !== "string" || !isAddress(value.to)) {
    throw new Error("Contract creation and missing transaction recipients are not supported");
  }
  const data = value.data ?? value.input ?? "0x";
  if (typeof data !== "string" || !isHex(data)) throw new Error("Transaction data must be hex");
  const encodedValue = value.value ?? "0x0";
  if (typeof encodedValue !== "string" || !isHex(encodedValue)) {
    throw new Error("Transaction value must be a hex quantity");
  }
  return {
    from: getAddress(value.from),
    to: getAddress(value.to),
    value: hexToBigInt(encodedValue as Hex),
    data: data as Hex,
  };
}

export function parsePersonalSign(params: unknown, account: Address): ParsedPersonalSign {
  if (!Array.isArray(params) || params.length < 2) {
    throw new Error("personal_sign requires a message and account");
  }
  const first = params[0];
  const second = params[1];
  const accountValue = addressMatchingAccount(first, account)
    ? first
    : addressMatchingAccount(second, account)
      ? second
      : undefined;
  const message = accountValue === first ? second : first;
  if (!accountValue) throw new Error(`personal_sign account must be ${account}`);
  if (typeof message !== "string" || !isHex(message)) {
    throw new Error("personal_sign message must be hex encoded");
  }
  return { account: getAddress(accountValue), message: message as Hex };
}

export function parseTypedData(
  params: unknown,
  account: Address,
  chainId = 84_532,
): ParsedTypedData {
  if (!Array.isArray(params) || params.length < 2) {
    throw new Error("eth_signTypedData_v4 requires an account and typed-data payload");
  }
  if (typeof params[0] !== "string" || !addressMatchingAccount(params[0], account)) {
    throw new Error(`Typed-data signer must be ${account}`);
  }
  let decoded: unknown = params[1];
  if (typeof decoded === "string") {
    try {
      decoded = JSON.parse(decoded);
    } catch {
      throw new Error("Typed-data payload is not valid JSON");
    }
  }
  if (!isRecord(decoded)) throw new Error("Typed-data payload must be an object");
  if (
    !isRecord(decoded.types) ||
    typeof decoded.primaryType !== "string" ||
    !isRecord(decoded.message)
  ) {
    throw new Error("Typed-data payload is missing types, primaryType, or message");
  }
  const domain = decoded.domain;
  if (domain !== undefined && !isRecord(domain))
    throw new Error("Typed-data domain must be an object");
  const domainChainId = domain?.chainId;
  if (domainChainId !== undefined && parseChainId(domainChainId) !== BigInt(chainId)) {
    throw new Error(`Typed-data chainId must be ${chainId}`);
  }
  const types: TypedDataPayload["types"] = {};
  for (const [typeName, fields] of Object.entries(decoded.types)) {
    if (!Array.isArray(fields))
      throw new Error(`Typed-data fields for ${typeName} must be an array`);
    types[typeName] = fields.map((field) => {
      if (!isRecord(field) || typeof field.name !== "string" || typeof field.type !== "string") {
        throw new Error(`Typed-data field in ${typeName} is invalid`);
      }
      return { name: field.name, type: field.type };
    });
  }
  return {
    account: getAddress(params[0]),
    typedData: {
      domain,
      types,
      primaryType: decoded.primaryType,
      message: decoded.message,
    },
  };
}

export async function executeWalletRequest(options: ExecuteWalletRequestOptions): Promise<Hex> {
  const walletChain = `eip155:${options.wallet.chain.id}`;
  if (options.chainId !== walletChain) throw new Error(`Unsupported chain ${options.chainId}`);
  switch (options.request.method) {
    case "eth_sendTransaction": {
      const transaction = parseTransaction(options.request.params, options.account);
      const result = await options.wallet.sendTransaction(
        options.account,
        options.device,
        { to: transaction.to, value: transaction.value, data: transaction.data },
        options.onStatus,
      );
      const transactionHash = result.receipt?.receipt.transactionHash;
      if (!transactionHash) throw new Error("Bundler returned no transaction hash");
      return transactionHash;
    }
    case "personal_sign": {
      const parsed = parsePersonalSign(options.request.params, options.account);
      return options.device.account.signMessage({ message: { raw: parsed.message } });
    }
    case "eth_signTypedData_v4": {
      const parsed = parseTypedData(
        options.request.params,
        options.account,
        options.wallet.chain.id,
      );
      return signTypedData(options.device.account, parsed.typedData);
    }
    default:
      throw new Error(`Unsupported wallet method ${options.request.method}`);
  }
}

function signTypedData(account: PrivateKeyAccount, typedData: TypedDataPayload): Promise<Hex> {
  return account.signTypedData(typedData as Parameters<PrivateKeyAccount["signTypedData"]>[0]);
}

function firstObject(params: unknown, label: string): Record<string, unknown> {
  if (!Array.isArray(params) || !isRecord(params[0])) throw new Error(`${label} are missing`);
  return params[0];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function addressMatchingAccount(value: unknown, account: Address): value is Address {
  return typeof value === "string" && isAddress(value) && isAddressEqual(value, account);
}

function parseChainId(value: unknown): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) return BigInt(value);
  throw new Error("Typed-data chainId must be an integer");
}
