import assert from "node:assert/strict";
import { getAddress } from "viem";
import {
  WALLET_STATE_KEY,
  clearWalletState,
  loadWalletState,
  saveWalletState,
} from "../src/wallet-state";

const factory = getAddress("0x1111111111111111111111111111111111111111");
const account = getAddress("0x2222222222222222222222222222222222222222");
const chainId = 84_532;
const storageKey = `${WALLET_STATE_KEY}.${chainId}`;

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(key: string) {
    return this.values.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.values.set(key, value);
  }
  removeItem(key: string) {
    this.values.delete(key);
  }
}

const storage = new MemoryStorage();
assert.deepEqual(saveWalletState(storage, factory, account, chainId), {
  version: 2,
  chainId,
  factory,
  account,
});
assert.deepEqual(loadWalletState(storage, factory, chainId), {
  version: 2,
  chainId,
  factory,
  account,
});

assert.equal(
  loadWalletState(storage, getAddress("0x3333333333333333333333333333333333333333"), chainId),
  undefined,
);
assert.equal(storage.getItem(storageKey), null);

storage.setItem(storageKey, "not-json");
assert.equal(loadWalletState(storage, factory, chainId), undefined);
assert.equal(storage.getItem(storageKey), null);

saveWalletState(storage, factory, account, chainId);
clearWalletState(storage, chainId);
assert.equal(storage.getItem(storageKey), null);

console.log("wallet state tests passed");
