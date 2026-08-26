import assert from "node:assert/strict";
import { getAddress } from "viem";
import { deviceIdentifier, type DeviceKey } from "@zkaccount/sdk";
import {
  WALLET_STATE_KEY,
  clearWalletState,
  loadWalletState,
  saveWalletState,
} from "../src/wallet-state";

const factory = getAddress("0x1111111111111111111111111111111111111111");
const account = getAddress("0x2222222222222222222222222222222222222222");
const chainId = 84_532;
const publicKeyX = `0x${"11".repeat(32)}` as const;
const publicKeyY = `0x${"22".repeat(32)}` as const;
const rpIdHash = `0x${"33".repeat(32)}` as const;
const device: DeviceKey = {
  address: deviceIdentifier(publicKeyX, publicKeyY, rpIdHash),
  credentialId: "0x01020304",
  publicKeyX,
  publicKeyY,
  rpId: "localhost",
  rpIdHash,
};
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
const legacyStorageKey = `zkaccount.demo-b.wallet.v2.${chainId}`;
storage.setItem(legacyStorageKey, JSON.stringify({ version: 2, chainId, factory, account }));
assert.equal(loadWalletState(storage, factory, chainId), undefined);
assert.equal(storage.getItem(legacyStorageKey), null);

assert.deepEqual(saveWalletState(storage, factory, account, chainId, device), {
  version: 3,
  chainId,
  factory,
  account,
  device,
});
assert.deepEqual(loadWalletState(storage, factory, chainId), {
  version: 3,
  chainId,
  factory,
  account,
  device,
});

assert.equal(
  loadWalletState(storage, getAddress("0x3333333333333333333333333333333333333333"), chainId),
  undefined,
);
assert.equal(storage.getItem(storageKey), null);

storage.setItem(storageKey, "not-json");
assert.equal(loadWalletState(storage, factory, chainId), undefined);
assert.equal(storage.getItem(storageKey), null);

saveWalletState(storage, factory, account, chainId, device);
clearWalletState(storage, chainId);
assert.equal(storage.getItem(storageKey), null);

console.log("wallet state tests passed");
