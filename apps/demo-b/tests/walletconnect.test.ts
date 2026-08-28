import assert from "node:assert/strict";
import type { IWalletKit, WalletKitTypes } from "@reown/walletkit";
import { getAddress } from "viem";
import {
  DemoBWalletConnectController,
  type SessionRequestPrompt,
  type WalletConnectCallbacks,
  type WalletPrompt,
} from "../src/walletconnect";

type Listener = (event: never) => void;

class MockWalletKit {
  readonly listeners = new Map<string, Listener>();
  readonly approved: unknown[] = [];
  readonly rejected: unknown[] = [];
  readonly responses: unknown[] = [];
  readonly disconnected: unknown[] = [];
  readonly sessions: Record<string, unknown> = {};
  readonly pending: unknown[] = [];

  on(event: string, listener: Listener) {
    this.listeners.set(event, listener);
    return this;
  }
  async pair() {}
  async approveSession(value: unknown) {
    this.approved.push(value);
    return {};
  }
  async rejectSession(value: unknown) {
    this.rejected.push(value);
  }
  async respondSessionRequest(value: unknown) {
    this.responses.push(value);
  }
  async disconnectSession(value: unknown) {
    this.disconnected.push(value);
  }
  getActiveSessions() {
    return this.sessions;
  }
  getPendingSessionRequests() {
    return this.pending;
  }
  emit(event: string, value: unknown) {
    this.listeners.get(event)?.(value as never);
  }
}

const mock = new MockWalletKit();
let activePrompt: WalletPrompt | undefined;
let sessionCount = -1;
let status = "";
const callbacks: WalletConnectCallbacks = {
  onPrompt: (prompt) => (activePrompt = prompt),
  onSessionsChanged: (count) => (sessionCount = count),
  onStatus: (value) => (status = value),
};
const controller = new DemoBWalletConnectController(
  mock as unknown as Pick<
    IWalletKit,
    | "on"
    | "pair"
    | "approveSession"
    | "rejectSession"
    | "respondSessionRequest"
    | "disconnectSession"
    | "getActiveSessions"
    | "getPendingSessionRequests"
  >,
  callbacks,
);
assert.equal(sessionCount, 0);

const metadata = { name: "Test dapp", description: "", url: "https://dapp.example", icons: [] };
const verifyContext = {
  verified: { origin: "https://dapp.example", validation: "VALID" as const, verifyUrl: "" },
};
const proposal = {
  id: 1,
  verifyContext,
  params: {
    id: 1,
    expiryTimestamp: Date.now() + 300_000,
    relays: [],
    proposer: { publicKey: "key", metadata },
    requiredNamespaces: {
      eip155: {
        chains: ["eip155:84532"],
        methods: ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4"],
        events: ["accountsChanged", "chainChanged"],
      },
    },
    optionalNamespaces: {},
    pairingTopic: "pairing",
  },
} as WalletKitTypes.SessionProposal;

mock.emit("session_proposal", proposal);
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(activePrompt?.kind, "session_proposal");
await assert.rejects(controller.approveProposal(activePrompt as never), /Load or recover/);
controller.setAccount(getAddress("0x1111111111111111111111111111111111111111"));
await controller.approveProposal(activePrompt as never);
assert.equal(mock.approved.length, 1);
assert.match(status, /Connected/);

mock.emit("session_proposal", {
  ...proposal,
  id: 2,
  params: {
    ...proposal.params,
    requiredNamespaces: {
      eip155: { chains: ["eip155:1"], methods: ["eth_sendTransaction"], events: [] },
    },
  },
});
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(mock.rejected.length, 1);
assert.match(status, /other than eip155:84532/);

mock.sessions.topic = { topic: "topic", peer: { metadata } };
const request = {
  id: 3,
  topic: "topic",
  verifyContext,
  params: {
    chainId: "eip155:84532",
    request: {
      method: "personal_sign",
      params: ["0x", "0x1111111111111111111111111111111111111111"],
    },
  },
} as WalletKitTypes.SessionRequest;
mock.emit("session_request", request);
assert.equal(activePrompt?.kind, "session_request");
await controller.approveRequest(activePrompt as never, "0xsigned");
assert.deepEqual(mock.responses[0], {
  topic: "topic",
  response: { id: 3, jsonrpc: "2.0", result: "0xsigned" },
});

mock.emit("session_request", {
  ...request,
  id: 4,
  params: { ...request.params, chainId: "eip155:1" },
});
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(mock.responses.length, 2);

mock.emit("session_request", { ...request, id: 5 });
mock.emit("session_request", { ...request, id: 6 });
assert.equal(controller.hasActivePrompt(), true);
assert.equal(activePrompt?.kind, "session_request");
await controller.approveRequest(activePrompt as SessionRequestPrompt, "0xfirst");
assert.equal(controller.hasActivePrompt(), true);
assert.equal((activePrompt as SessionRequestPrompt).event.id, 6);
await controller.rejectRequest(activePrompt as SessionRequestPrompt);
assert.equal(controller.hasActivePrompt(), false);

await controller.disconnect("topic");
assert.equal(mock.disconnected.length, 1);

console.log("wallet controller tests passed");
