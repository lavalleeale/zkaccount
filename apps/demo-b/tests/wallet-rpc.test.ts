import assert from "node:assert/strict";
import { bytesToHex, getAddress, hashMessage, hashTypedData, type Address, type Hex } from "viem";
import { deviceIdentifier, type DeviceKey, type Google4337Client } from "@zkaccount/sdk";
import {
  executeWalletRequest,
  parsePersonalSign,
  parseTransaction,
  parseTypedData,
} from "../src/wallet-rpc";

const walletChain = "eip155:84532";

const smartAccount = getAddress("0x1111111111111111111111111111111111111111");
const recipient = getAddress("0x2222222222222222222222222222222222222222");
const publicKeyX = `0x${"11".repeat(32)}` as Hex;
const publicKeyY = `0x${"22".repeat(32)}` as Hex;
const rpIdHash = `0x${"33".repeat(32)}` as Hex;
const device: DeviceKey = {
  address: deviceIdentifier(publicKeyX, publicKeyY, rpIdHash),
  credentialId: "0x01020304",
  publicKeyX,
  publicKeyY,
  rpIdHash,
};
const signedChallenges: Hex[] = [];
Object.defineProperty(globalThis, "window", {
  value: { isSecureContext: true, PublicKeyCredential: class {} },
});
Object.defineProperty(globalThis, "navigator", {
  value: {
    credentials: {
      get: async ({ publicKey }: CredentialRequestOptions) => {
        const challenge = new Uint8Array(publicKey!.challenge as ArrayBuffer);
        signedChallenges.push(bytesToHex(challenge));
        const encodedChallenge = Buffer.from(challenge).toString("base64url");
        const authenticatorData = new Uint8Array(37);
        authenticatorData.set(new Uint8Array(Buffer.from(rpIdHash.slice(2), "hex")));
        authenticatorData[32] = 0x05;
        const clientDataJSON = new TextEncoder().encode(
          `{"type":"webauthn.get","challenge":"${encodedChallenge}","origin":"http://localhost:5174","crossOrigin":false}`,
        );
        return {
          rawId: Uint8Array.from([1, 2, 3, 4]).buffer,
          response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON.buffer,
            signature: Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01]).buffer,
          },
        };
      },
    },
  },
});

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
assert.ok(personalSignature.startsWith("0x00"));
assert.equal(signedChallenges[0], hashMessage({ raw: "0x6869" }));

const typedSignature = await executeWalletRequest({
  chainId: walletChain,
  request: { method: "eth_signTypedData_v4", params: [smartAccount, typedData] },
  account: smartAccount,
  device,
  wallet: { chain: { id: 84532 } } as Google4337Client,
});
assert.ok(typedSignature.startsWith("0x00"));
assert.equal(signedChallenges[1], hashTypedData(typedData));

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
