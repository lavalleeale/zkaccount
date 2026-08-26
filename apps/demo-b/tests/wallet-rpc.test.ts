import assert from "node:assert/strict";
import { getAddress, hashMessage, hashTypedData, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { DeviceKey, Google4337Client } from "@zkaccount/sdk";
import {
  executeWalletRequest,
  parsePersonalSign,
  parseTransaction,
  parseTypedData,
} from "../src/wallet-rpc";

const walletChain = "eip155:84532";

const smartAccount = getAddress("0x1111111111111111111111111111111111111111");
const recipient = getAddress("0x2222222222222222222222222222222222222222");
const deviceAccount = privateKeyToAccount(
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
);
const device: DeviceKey = {
  address: deviceAccount.address,
  account: deviceAccount,
  protection: "passkey-prf",
};

assert.deepEqual(
  parseTransaction(
    [{ from: smartAccount, to: recipient, value: "0x2a", data: "0x1234" }],
    smartAccount,
  ),
  { from: smartAccount, to: recipient, value: 42n, data: "0x1234" },
);
assert.throws(
  () => parseTransaction([{ from: recipient, to: recipient }], smartAccount),
  /active smart account/,
);
assert.throws(() => parseTransaction([{ from: smartAccount }], smartAccount), /not supported/);

assert.deepEqual(parsePersonalSign(["0x6869", smartAccount], smartAccount), {
  account: smartAccount,
  message: "0x6869",
});
assert.deepEqual(parsePersonalSign([smartAccount, "0x6869"], smartAccount), {
  account: smartAccount,
  message: "0x6869",
});
assert.throws(() => parsePersonalSign(["hello", smartAccount], smartAccount), /hex encoded/);

const typedData = {
  domain: { name: "Demo", version: "1", chainId: 84532 },
  types: { Message: [{ name: "contents", type: "string" }] },
  primaryType: "Message",
  message: { contents: "hello" },
};
assert.deepEqual(
  parseTypedData([smartAccount, JSON.stringify(typedData)], smartAccount).typedData,
  typedData,
);
assert.throws(
  () =>
    parseTypedData(
      [smartAccount, JSON.stringify({ ...typedData, domain: { chainId: 1 } })],
      smartAccount,
    ),
  /chainId must be 84532/,
);

const personalSignature = await executeWalletRequest({
  chainId: walletChain,
  request: { method: "personal_sign", params: ["0x6869", smartAccount] },
  account: smartAccount,
  device,
  wallet: { chain: { id: 84532 } } as Google4337Client,
});
assert.equal(await deviceAccount.sign({ hash: hashMessage({ raw: "0x6869" }) }), personalSignature);

const typedSignature = await executeWalletRequest({
  chainId: walletChain,
  request: { method: "eth_signTypedData_v4", params: [smartAccount, typedData] },
  account: smartAccount,
  device,
  wallet: { chain: { id: 84532 } } as Google4337Client,
});
assert.equal(await deviceAccount.sign({ hash: hashTypedData(typedData) }), typedSignature);

let submitted:
  | {
      account: Address;
      device: DeviceKey;
      transaction: { to: Address; value?: bigint; data?: Hex };
    }
  | undefined;
const transactionHash = `0x${"12".repeat(32)}` as Hex;
const wallet = {
  chain: { id: 84532 },
  async sendTransaction(
    account: Address,
    signingDevice: DeviceKey,
    transaction: { to: Address; value?: bigint; data?: Hex },
  ) {
    submitted = { account, device: signingDevice, transaction };
    return { accountAddress: account, receipt: { receipt: { transactionHash } } };
  },
} as unknown as Google4337Client;
assert.equal(
  await executeWalletRequest({
    chainId: walletChain,
    request: {
      method: "eth_sendTransaction",
      params: [{ from: smartAccount, to: recipient, value: "0x1", data: "0xab" }],
    },
    account: smartAccount,
    device,
    wallet,
  }),
  transactionHash,
);
assert.deepEqual(submitted?.transaction, { to: recipient, value: 1n, data: "0xab" });

await assert.rejects(
  executeWalletRequest({
    chainId: "eip155:1",
    request: { method: "personal_sign", params: ["0x", smartAccount] },
    account: smartAccount,
    device,
    wallet,
  }),
  /Unsupported chain/,
);

console.log("wallet RPC tests passed");
