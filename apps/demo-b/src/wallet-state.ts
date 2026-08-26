import { getAddress, isAddressEqual, type Address } from "viem";

export const WALLET_STATE_KEY = "zkaccount.demo-b.wallet.v2";
export const WALLET_STATE_VERSION = 2;

export interface StoredWalletState {
  version: typeof WALLET_STATE_VERSION;
  chainId: number;
  factory: Address;
  account: Address;
}

export function loadWalletState(
  storage: Pick<Storage, "getItem" | "removeItem">,
  factory: Address,
  chainId: number,
): StoredWalletState | undefined {
  const key = `${WALLET_STATE_KEY}.${chainId}`;
  const encoded = storage.getItem(key);
  if (!encoded) return undefined;
  try {
    const candidate = JSON.parse(encoded) as Partial<StoredWalletState>;
    if (
      candidate.version !== WALLET_STATE_VERSION ||
      candidate.chainId !== chainId ||
      !candidate.factory ||
      !candidate.account ||
      !isAddressEqual(getAddress(candidate.factory), factory)
    ) {
      storage.removeItem(key);
      return undefined;
    }
    return {
      version: WALLET_STATE_VERSION,
      chainId,
      factory: getAddress(candidate.factory),
      account: getAddress(candidate.account),
    };
  } catch {
    storage.removeItem(key);
    return undefined;
  }
}

export function saveWalletState(
  storage: Pick<Storage, "setItem">,
  factory: Address,
  account: Address,
  chainId: number,
): StoredWalletState {
  const state: StoredWalletState = {
    version: WALLET_STATE_VERSION,
    chainId,
    factory: getAddress(factory),
    account: getAddress(account),
  };
  storage.setItem(`${WALLET_STATE_KEY}.${chainId}`, JSON.stringify(state));
  return state;
}

export function clearWalletState(storage: Pick<Storage, "removeItem">, chainId: number): void {
  storage.removeItem(`${WALLET_STATE_KEY}.${chainId}`);
}
