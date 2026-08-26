import { Core } from "@walletconnect/core";
import { WalletKit, type IWalletKit, type WalletKitTypes } from "@reown/walletkit";
import { buildApprovedNamespaces, getSdkError } from "@walletconnect/utils";
import type { Address } from "viem";
import { WALLET_EVENTS, WALLET_METHODS } from "./wallet-rpc";

type WalletKitClient = Pick<
  IWalletKit,
  | "on"
  | "pair"
  | "approveSession"
  | "rejectSession"
  | "respondSessionRequest"
  | "disconnectSession"
  | "getActiveSessions"
  | "getPendingSessionRequests"
>;

export interface VerificationInfo {
  origin: string;
  validation: "UNKNOWN" | "VALID" | "INVALID";
  isScam: boolean;
}

export interface PeerInfo {
  name: string;
  description: string;
  url: string;
  icons: string[];
  redirect?: { native?: string; universal?: string };
}

export interface SessionProposalPrompt {
  kind: "session_proposal";
  key: string;
  event: WalletKitTypes.SessionProposal;
  peer: PeerInfo;
  verification: VerificationInfo;
}

export interface SessionRequestPrompt {
  kind: "session_request";
  key: string;
  event: WalletKitTypes.SessionRequest;
  peer: PeerInfo;
  verification: VerificationInfo;
}

export type WalletPrompt = SessionProposalPrompt | SessionRequestPrompt;

export interface WalletConnectCallbacks {
  onPrompt(prompt: WalletPrompt | undefined): void;
  onSessionsChanged(sessionCount: number): void;
  onStatus(status: string): void;
}

export class DemoBWalletConnectController {
  private account?: Address;
  private readonly queue: WalletPrompt[] = [];
  private active?: WalletPrompt;

  constructor(
    private readonly client: WalletKitClient,
    private readonly callbacks: WalletConnectCallbacks,
    readonly chainId = 84_532,
  ) {
    client.on("session_proposal", (event) => void this.handleProposal(event));
    client.on("session_request", (event) => this.handleRequest(event));
    client.on("session_delete", () => this.emitSessionCount());
    this.emitSessionCount();
  }

  setAccount(account: Address | undefined): void {
    this.account = account;
  }

  async pair(uri: string): Promise<void> {
    const trimmed = uri.trim();
    if (!trimmed.startsWith("wc:")) throw new Error("Enter a valid WalletConnect URI");
    this.callbacks.onStatus("Pairing with dapp");
    await this.client.pair({ uri: trimmed });
    this.callbacks.onStatus("Pairing received. Review the connection request.");
  }

  async approveProposal(prompt: SessionProposalPrompt): Promise<void> {
    this.assertActive(prompt);
    if (!this.account) throw new Error("Unlock or recover the smart account before connecting");
    const proposal = prompt.event.params;
    const namespaces = buildApprovedNamespaces({
      proposal,
      supportedNamespaces: supportedNamespaces(this.account, this.walletChain),
    });
    await this.client.approveSession({ id: prompt.event.id, namespaces });
    this.callbacks.onStatus(`Connected to ${prompt.peer.name}`);
    this.finish(prompt);
    this.emitSessionCount();
  }

  async rejectProposal(prompt: SessionProposalPrompt): Promise<void> {
    this.assertActive(prompt);
    await this.client.rejectSession({
      id: prompt.event.id,
      reason: getSdkError("USER_REJECTED"),
    });
    this.callbacks.onStatus(`Rejected connection from ${prompt.peer.name}`);
    this.finish(prompt);
  }

  async approveRequest(prompt: SessionRequestPrompt, result: string): Promise<void> {
    this.assertActive(prompt);
    await this.client.respondSessionRequest({
      topic: prompt.event.topic,
      response: { id: prompt.event.id, jsonrpc: "2.0", result },
    });
    this.callbacks.onStatus(`${prompt.event.params.request.method} completed`);
    this.finish(prompt);
  }

  async rejectRequest(
    prompt: SessionRequestPrompt,
    message = "User rejected request",
  ): Promise<void> {
    this.assertActive(prompt);
    await this.client.respondSessionRequest({
      topic: prompt.event.topic,
      response: { id: prompt.event.id, jsonrpc: "2.0", error: { code: 4001, message } },
    });
    this.callbacks.onStatus(message);
    this.finish(prompt);
  }

  async disconnect(topic: string): Promise<void> {
    await this.client.disconnectSession({ topic, reason: getSdkError("USER_DISCONNECTED") });
    this.emitSessionCount();
  }

  sessions(): Array<{ topic: string; peer: PeerInfo }> {
    return Object.values(this.client.getActiveSessions()).map((session) => ({
      topic: session.topic,
      peer: session.peer.metadata,
    }));
  }

  restorePendingRequest(requestId: number, sessionTopic: string): boolean {
    const request = this.client
      .getPendingSessionRequests()
      .find((candidate) => candidate.id === requestId && candidate.topic === sessionTopic);
    if (!request) return false;
    this.handleRequest(request);
    return true;
  }

  private async handleProposal(event: WalletKitTypes.SessionProposal): Promise<void> {
    try {
      assertProposalSupported(event, this.walletChain);
      this.enqueue({
        kind: "session_proposal",
        key: `proposal:${event.id}`,
        event,
        peer: event.params.proposer.metadata,
        verification: verification(event),
      });
    } catch (error) {
      await this.client.rejectSession({
        id: event.id,
        reason: getSdkError("USER_REJECTED_METHODS"),
      });
      this.callbacks.onStatus(error instanceof Error ? error.message : String(error));
    }
  }

  private handleRequest(event: WalletKitTypes.SessionRequest): void {
    if (
      event.params.chainId !== this.walletChain ||
      !isSupportedMethod(event.params.request.method)
    ) {
      void this.client.respondSessionRequest({
        topic: event.topic,
        response: {
          id: event.id,
          jsonrpc: "2.0",
          error: { code: 4200, message: `Unsupported request ${event.params.request.method}` },
        },
      });
      return;
    }
    const session = this.client.getActiveSessions()[event.topic];
    this.enqueue({
      kind: "session_request",
      key: `request:${event.topic}:${event.id}`,
      event,
      peer: session?.peer.metadata ?? unknownPeer(),
      verification: verification(event),
    });
  }

  private enqueue(prompt: WalletPrompt): void {
    if (
      this.active?.key === prompt.key ||
      this.queue.some((candidate) => candidate.key === prompt.key)
    ) {
      return;
    }
    if (!this.active) {
      this.active = prompt;
      this.callbacks.onPrompt(prompt);
    } else {
      this.queue.push(prompt);
    }
  }

  private finish(prompt: WalletPrompt): void {
    this.assertActive(prompt);
    this.active = this.queue.shift();
    this.callbacks.onPrompt(this.active);
  }

  private assertActive(prompt: WalletPrompt): void {
    if (this.active?.key !== prompt.key) throw new Error("Wallet request is no longer active");
  }

  private emitSessionCount(): void {
    this.callbacks.onSessionsChanged(Object.keys(this.client.getActiveSessions()).length);
  }

  private get walletChain(): `eip155:${number}` {
    return `eip155:${this.chainId}`;
  }
}

export async function createWalletConnectController(
  projectId: string,
  chainId: number,
  callbacks: WalletConnectCallbacks,
): Promise<DemoBWalletConnectController> {
  const core = new Core({ projectId });
  const client = await WalletKit.init({
    core,
    metadata: {
      name: "zkAccount Demo B",
      description: "Google-recoverable ERC-4337 smart wallet",
      url: window.location.origin,
      icons: [`${window.location.origin}/wallet-icon.svg`],
      redirect: { universal: `${window.location.origin}/wc` },
    },
  });
  return new DemoBWalletConnectController(client, callbacks, chainId);
}

export function describePrompt(prompt: WalletPrompt): Record<string, string> {
  if (prompt.kind === "session_proposal") {
    return {
      Request: "Connect wallet",
      Dapp: prompt.peer.name,
      Origin: prompt.verification.origin || prompt.peer.url,
      Verification: verificationLabel(prompt.verification),
      Chains: requestedValues(prompt.event.params.requiredNamespaces, "chains"),
      Methods: requestedValues(prompt.event.params.requiredNamespaces, "methods"),
    };
  }
  const request = prompt.event.params.request;
  const details: Record<string, string> = {
    Request: request.method,
    Dapp: prompt.peer.name,
    Origin: prompt.verification.origin || prompt.peer.url,
    Verification: verificationLabel(prompt.verification),
    Chain: prompt.event.params.chainId,
  };
  if (request.method === "eth_sendTransaction" && Array.isArray(request.params)) {
    const transaction = request.params[0];
    if (typeof transaction === "object" && transaction !== null) {
      const values = transaction as Record<string, unknown>;
      details.From = String(values.from ?? "");
      details.To = String(values.to ?? "");
      details.Value = String(values.value ?? "0x0");
      details.Data = String(values.data ?? values.input ?? "0x");
    }
  } else {
    details.Payload = safeStringify(request.params);
  }
  return details;
}

function supportedNamespaces(account: Address, walletChain: `eip155:${number}`) {
  return {
    eip155: {
      chains: [walletChain],
      methods: [...WALLET_METHODS],
      events: [...WALLET_EVENTS],
      accounts: [`${walletChain}:${account}`],
    },
  };
}

function assertProposalSupported(
  event: WalletKitTypes.SessionProposal,
  walletChain: `eip155:${number}`,
): void {
  const required = event.params.requiredNamespaces;
  for (const [namespace, request] of Object.entries(required)) {
    if (namespace !== "eip155" && namespace !== walletChain) {
      throw new Error(`Rejected unsupported namespace ${namespace}`);
    }
    if (request.chains?.some((chain) => chain !== walletChain)) {
      throw new Error(`Rejected connection requesting a chain other than ${walletChain}`);
    }
    if (request.methods.some((method) => !isSupportedMethod(method))) {
      throw new Error("Rejected connection requesting unsupported wallet methods");
    }
    if (
      request.events.some(
        (eventName) => !WALLET_EVENTS.includes(eventName as (typeof WALLET_EVENTS)[number]),
      )
    ) {
      throw new Error("Rejected connection requesting unsupported wallet events");
    }
  }
}

function isSupportedMethod(method: string): method is (typeof WALLET_METHODS)[number] {
  return WALLET_METHODS.includes(method as (typeof WALLET_METHODS)[number]);
}

function verification(event: {
  verifyContext: WalletKitTypes.SessionProposal["verifyContext"];
}): VerificationInfo {
  return {
    origin: event.verifyContext.verified.origin,
    validation: event.verifyContext.verified.validation,
    isScam: event.verifyContext.verified.isScam === true,
  };
}

function verificationLabel(info: VerificationInfo): string {
  if (info.isScam) return "Known scam warning";
  if (info.validation === "VALID") return "Verified domain";
  if (info.validation === "INVALID") return "Domain mismatch";
  return "Unknown domain";
}

function requestedValues(
  namespaces: Record<string, { chains?: string[]; methods: string[] }>,
  key: "chains" | "methods",
): string {
  return [...new Set(Object.values(namespaces).flatMap((namespace) => namespace[key] ?? []))].join(
    ", ",
  );
}

function unknownPeer(): PeerInfo {
  return { name: "Unknown dapp", description: "", url: "", icons: [] };
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
