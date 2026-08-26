import { type Address, type Hex } from "viem";
import {
  encodeP256PublicKey,
  publicDeviceFromRpIdAndPublicKey,
  type DeviceKey,
  type PublicDeviceKey,
} from "./account";

export const PASSKEY_RESULT_PREFIX = "zkaccount_";

export interface PasskeyAuthorizationRequest {
  rpId: string;
  publicKey: Hex;
  callback: URL;
  state: string;
  chainId: number;
  device: PublicDeviceKey;
}

export type PasskeyAuthorizationStatus = "approved" | "rejected" | "failed";

export interface PasskeyAuthorizationResult {
  status: PasskeyAuthorizationStatus;
  state: string;
  chainId: number;
  account?: Address;
  device?: Address;
  error?: string;
}

export async function parsePasskeyAuthorizationRequest(
  search: string,
  supportedChainIds: readonly number[],
): Promise<PasskeyAuthorizationRequest> {
  const params = new URLSearchParams(search);
  const rpId = required(params, "rpId").trim().toLowerCase().replace(/\.$/, "");
  const publicKey = required(params, "publicKey") as Hex;
  const callback = parseCallback(required(params, "callback"));
  const state = required(params, "state");
  if (!/^[A-Za-z0-9_-]{43}$/.test(state))
    throw new Error("State must be a 32-byte base64url value");
  const chainId = Number(required(params, "chainId"));
  if (!Number.isSafeInteger(chainId) || !supportedChainIds.includes(chainId)) {
    throw new Error("Requested chain is not supported by this passkey manager");
  }
  if (callback.hostname.toLowerCase().replace(/\.$/, "") !== rpId) {
    throw new Error("Callback hostname must exactly match the requested RP ID");
  }
  return {
    rpId,
    publicKey,
    callback,
    state,
    chainId,
    device: await publicDeviceFromRpIdAndPublicKey(rpId, publicKey),
  };
}

export function createPasskeyAuthorizationUrl(options: {
  managerUrl: string;
  callback: string;
  chainId: number;
  device: DeviceKey;
  state?: string;
}): { url: URL; state: string } {
  const state = options.state ?? randomState();
  const url = new URL(options.managerUrl);
  url.searchParams.set("rpId", options.device.rpId);
  url.searchParams.set("publicKey", encodeP256PublicKey(options.device));
  url.searchParams.set("callback", options.callback);
  url.searchParams.set("state", state);
  url.searchParams.set("chainId", String(options.chainId));
  return { url, state };
}

export function createPasskeyResultUrl(
  callback: URL | string,
  result: PasskeyAuthorizationResult,
): URL {
  const url = new URL(callback.toString());
  url.searchParams.set(`${PASSKEY_RESULT_PREFIX}state`, result.state);
  url.searchParams.set(`${PASSKEY_RESULT_PREFIX}status`, result.status);
  url.searchParams.set(`${PASSKEY_RESULT_PREFIX}chain_id`, String(result.chainId));
  setOptional(url, "account", result.account);
  setOptional(url, "device", result.device);
  setOptional(url, "error", result.error);
  return url;
}

export function parsePasskeyAuthorizationResult(
  search: string,
): PasskeyAuthorizationResult | undefined {
  const params = new URLSearchParams(search);
  const status = params.get(`${PASSKEY_RESULT_PREFIX}status`);
  if (status !== "approved" && status !== "rejected" && status !== "failed") return undefined;
  const chainId = Number(params.get(`${PASSKEY_RESULT_PREFIX}chain_id`));
  return {
    status,
    state: params.get(`${PASSKEY_RESULT_PREFIX}state`) ?? "",
    chainId,
    account: asAddress(params.get(`${PASSKEY_RESULT_PREFIX}account`)),
    device: asAddress(params.get(`${PASSKEY_RESULT_PREFIX}device`)),
    error: params.get(`${PASSKEY_RESULT_PREFIX}error`) ?? undefined,
  };
}

function parseCallback(value: string): URL {
  let callback: URL;
  try {
    callback = new URL(value);
  } catch {
    throw new Error("Callback must be an absolute URL");
  }
  const host = callback.hostname.toLowerCase();
  const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  if (
    callback.username ||
    callback.password ||
    callback.hash ||
    (callback.protocol !== "https:" && !(callback.protocol === "http:" && loopback))
  ) {
    throw new Error("Callback must be HTTPS (or HTTP localhost) without credentials or fragments");
  }
  return callback;
}
function required(params: URLSearchParams, key: string): string {
  const value = params.get(key);
  if (!value) throw new Error(`Missing ${key} query parameter`);
  return value;
}
function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function setOptional(url: URL, key: string, value: string | undefined): void {
  const name = `${PASSKEY_RESULT_PREFIX}${key}`;
  if (value) url.searchParams.set(name, value);
  else url.searchParams.delete(name);
}
function asAddress(value: string | null): Address | undefined {
  return value && /^0x[0-9a-fA-F]{40}$/.test(value) ? (value as Address) : undefined;
}
