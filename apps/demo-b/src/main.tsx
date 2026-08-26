import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { formatEther, isAddressEqual, type Address } from "viem";
import { baseSepolia, sepolia } from "viem/chains";
import {
  Google4337Client,
  createPasskeyAuthorizationUrl,
  createPasskeyDeviceKey,
  loadPasskeyDeviceKey,
  parsePasskeyAuthorizationResult,
  type DeviceKey,
  type PasskeyAuthorizationResult,
} from "@zkaccount/sdk";
import {
  createWalletConnectController,
  describePrompt,
  type DemoBWalletConnectController,
  type SessionProposalPrompt,
  type SessionRequestPrompt,
  type WalletPrompt,
} from "./walletconnect";
import { executeWalletRequest } from "./wallet-rpc";
import {
  clearWalletState,
  loadWalletState,
  saveWalletState,
  type StoredWalletState,
} from "./wallet-state";
import "../../demo-a/src/style.css";
import "./wallet.css";

const managerUrl = import.meta.env.VITE_PASSKEY_MANAGER_URL as string | undefined;
const PENDING_KEY = "zkaccount.demo-b.pending-authorization.v1";
const NETWORK_KEY = "zkaccount.selected-network";
const networks = {
  "base-sepolia": {
    chain: baseSepolia,
    factory: (import.meta.env.VITE_BASE_SEPOLIA_FACTORY ?? import.meta.env.VITE_ACCOUNT_FACTORY) as
      Address | undefined,
    rpcUrl: (import.meta.env.VITE_BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org") as string,
    bundlerUrl: (import.meta.env.VITE_BASE_SEPOLIA_BUNDLER_URL ??
      import.meta.env.VITE_BUNDLER_URL) as string | undefined,
    factoryDeploymentBlock: 45_974_182n,
  },
  "ethereum-sepolia": {
    chain: sepolia,
    factory: import.meta.env.VITE_ETHEREUM_SEPOLIA_FACTORY as Address | undefined,
    rpcUrl: (import.meta.env.VITE_ETHEREUM_SEPOLIA_RPC_URL ??
      "https://ethereum-sepolia-rpc.publicnode.com") as string,
    bundlerUrl: import.meta.env.VITE_ETHEREUM_SEPOLIA_BUNDLER_URL as string | undefined,
    factoryDeploymentBlock: BigInt(
      (import.meta.env.VITE_ETHEREUM_SEPOLIA_FACTORY_DEPLOYMENT_BLOCK as string | undefined) ?? "0",
    ),
  },
} as const;
type NetworkKey = keyof typeof networks;
const selectedNetworkKey: NetworkKey =
  window.localStorage.getItem(NETWORK_KEY) === "ethereum-sepolia"
    ? "ethereum-sepolia"
    : "base-sepolia";
const network = networks[selectedNetworkKey];
const { factory, rpcUrl, bundlerUrl } = network;
const reownProjectId = import.meta.env.VITE_REOWN_PROJECT_ID as string | undefined;
const passkeyOptions = { scope: "demo-b", displayName: "zkAccount Demo B" };

interface PendingAuthorization {
  state: string;
  chainId: number;
  device: DeviceKey;
}

function savePendingAuthorization(pending: PendingAuthorization): void {
  window.sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
}

function takePendingAuthorization(): PendingAuthorization | undefined {
  const raw = window.sessionStorage.getItem(PENDING_KEY);
  window.sessionStorage.removeItem(PENDING_KEY);
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw) as Partial<PendingAuthorization>;
    if (typeof parsed.state !== "string" || typeof parsed.chainId !== "number" || !parsed.device) {
      return undefined;
    }
    return {
      state: parsed.state,
      chainId: parsed.chainId,
      device: loadPasskeyDeviceKey(parsed.device),
    };
  } catch {
    return undefined;
  }
}

function App() {
  const walletConnect = useRef<DemoBWalletConnectController | undefined>(undefined);
  const wallet = useMemo(
    () =>
      factory
        ? new Google4337Client({
            factory,
            bundlerUrl: bundlerUrl ?? "",
            rpcUrl,
            chain: network.chain,
            factoryDeploymentBlock: network.factoryDeploymentBlock,
          })
        : undefined,
    [],
  );
  const initialStored = useMemo(
    () => (factory ? loadWalletState(window.localStorage, factory, network.chain.id) : undefined),
    [],
  );
  const [stored, setStored] = useState<StoredWalletState | undefined>(initialStored);
  const [status, setStatus] = useState(
    initialStored
      ? "Known smart account is ready. Confirm each signature with its passkey."
      : "Ready",
  );
  const [device, setDevice] = useState<DeviceKey | undefined>(initialStored?.device);
  const [account, setAccount] = useState<Address | undefined>(initialStored?.account);
  const [balance, setBalance] = useState(0n);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pairingUri, setPairingUri] = useState("");
  const [prompt, setPrompt] = useState<WalletPrompt>();
  const [returnUrl, setReturnUrl] = useState<string>();
  const [sessions, setSessions] = useState<
    Array<{ topic: string; peer: { name: string; url: string } }>
  >([]);
  const [walletConnectReady, setWalletConnectReady] = useState(false);

  async function handleAuthorizationResult(
    result: PasskeyAuthorizationResult,
    pending: PendingAuthorization | undefined,
  ) {
    if (!pending || pending.state !== result.state) {
      setStatus("This passkey authorization result is missing, expired, or was already used.");
      return;
    }
    if (result.chainId !== pending.chainId) {
      setStatus("This passkey authorization result is for a different network.");
      return;
    }
    if (result.status === "rejected") {
      setStatus("Passkey authorization was rejected.");
      return;
    }
    if (
      result.status !== "approved" ||
      !result.account ||
      !result.device ||
      !isAddressEqual(result.device, pending.device.address)
    ) {
      setStatus(
        result.status === "failed" && result.error
          ? `Passkey authorization failed: ${result.error}`
          : "Passkey authorization failed.",
      );
      return;
    }
    if (!wallet || !factory) {
      setStatus("Set VITE_ACCOUNT_FACTORY first");
      return;
    }
    setBusy(true);
    try {
      setStatus("Verifying on-chain authorization");
      const isAuthorized = await wallet.isDeviceAuthorized(result.account, pending.device.address);
      if (!isAuthorized) {
        throw new Error(
          "The passkey manager reported success, but the device is not authorized onchain",
        );
      }
      setDevice(pending.device);
      setAccount(result.account);
      setAuthorized(true);
      setStored(
        saveWalletState(
          window.localStorage,
          factory,
          result.account,
          pending.chainId,
          pending.device,
        ),
      );
      setBalance(await wallet.getBalance(result.account));
      setStatus("Wallet ready. Your passkey will be requested for each signature.");
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const result = parsePasskeyAuthorizationResult(window.location.search);
    if (!result) return;
    window.history.replaceState(null, "", window.location.pathname);
    const pending = takePendingAuthorization();
    queueMicrotask(() => void handleAuthorizationResult(result, pending));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!reownProjectId) return;
    let disposed = false;
    void createWalletConnectController(reownProjectId, network.chain.id, {
      onPrompt: setPrompt,
      onSessionsChanged: () =>
        queueMicrotask(() => setSessions(walletConnect.current?.sessions() ?? [])),
      onStatus: setStatus,
    })
      .then(async (controller) => {
        if (disposed) return;
        walletConnect.current = controller;
        controller.setAccount(initialStored?.account);
        setSessions(controller.sessions());
        setWalletConnectReady(true);
        const params = new URLSearchParams(window.location.search);
        const uri = params.get("uri");
        if (uri) {
          setPairingUri(uri);
          await controller.pair(uri);
        }
        const requestId = Number(params.get("requestId"));
        const sessionTopic = params.get("sessionTopic");
        if (Number.isSafeInteger(requestId) && requestId > 0 && sessionTopic) {
          if (!controller.restorePendingRequest(requestId, sessionTopic)) {
            setStatus("The linked WalletConnect request was not found or has expired");
          }
        }
      })
      .catch((error: unknown) => setStatus(errorMessage(error)));
    return () => {
      disposed = true;
    };
  }, [initialStored?.account]);

  useEffect(() => walletConnect.current?.setAccount(account), [account]);

  async function loadStoredWallet() {
    if (!stored || !wallet) {
      setStatus("No stored wallet was found; create a passkey to get started");
      return;
    }
    setBusy(true);
    setStatus("Loading stored passkey metadata");
    try {
      const nextDevice = loadPasskeyDeviceKey(stored.device);
      setDevice(nextDevice);
      setStatus("Checking the stored smart account authorization");
      const stillAuthorized = await wallet.isDeviceAuthorized(stored.account, nextDevice.address);
      if (stillAuthorized) {
        setAccount(stored.account);
        setAuthorized(true);
        setBalance(await wallet.getBalance(stored.account));
        setStatus("Wallet ready. Your passkey will be requested for each signature.");
        return;
      }
      clearWalletState(window.localStorage, network.chain.id);
      setStored(undefined);
      setAccount(undefined);
      setAuthorized(false);
      setStatus(
        "This passkey is no longer authorized. Create a new passkey to recover the account.",
      );
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function createPasskeyAndAuthorize() {
    if (!managerUrl) {
      setStatus("Set VITE_PASSKEY_MANAGER_URL to the passkey manager's origin first");
      return;
    }
    setBusy(true);
    setStatus("Creating Demo B passkey");
    try {
      const newDevice = await createPasskeyDeviceKey(passkeyOptions);
      const { url, state } = createPasskeyAuthorizationUrl({
        managerUrl,
        callback: `${window.location.origin}/`,
        chainId: network.chain.id,
        device: newDevice,
      });
      savePendingAuthorization({ state, chainId: network.chain.id, device: newDevice });
      setStatus("Redirecting to the passkey manager for Google authorization");
      window.location.href = url.toString();
    } catch (error) {
      setStatus(errorMessage(error));
      setBusy(false);
    }
  }

  async function refresh() {
    if (!wallet || !account || !device) return;
    const [nextBalance, nextAuthorized] = await Promise.all([
      wallet.getBalance(account),
      wallet.isDeviceAuthorized(account, device.address),
    ]);
    setBalance(nextBalance);
    setAuthorized(nextAuthorized);
    if (!nextAuthorized) {
      clearWalletState(window.localStorage, network.chain.id);
      setStored(undefined);
    }
    setStatus(nextAuthorized ? "Wallet is ready" : "This device needs to be re-authorized");
  }

  async function pair() {
    if (!walletConnect.current) {
      setStatus("Set VITE_REOWN_PROJECT_ID and wait for WalletConnect to initialize");
      return;
    }
    setBusy(true);
    try {
      await walletConnect.current.pair(pairingUri);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function approveProposal(activePrompt: SessionProposalPrompt) {
    if (!authorized) {
      setStatus("Load and authorize the passkey before connecting");
      return;
    }
    setBusy(true);
    try {
      await walletConnect.current?.approveProposal(activePrompt);
      setReturnUrl(activePrompt.peer.redirect?.universal ?? activePrompt.peer.url);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function rejectProposal(activePrompt: SessionProposalPrompt) {
    setBusy(true);
    try {
      await walletConnect.current?.rejectProposal(activePrompt);
      setReturnUrl(activePrompt.peer.redirect?.universal ?? activePrompt.peer.url);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function approveRequest(activePrompt: SessionRequestPrompt) {
    if (!wallet || !account || !device || !authorized || !walletConnect.current) {
      setStatus("Load the authorized passkey before approving this request");
      return;
    }
    setBusy(true);
    try {
      if (!(await wallet.isDeviceAuthorized(account, device.address))) {
        clearWalletState(window.localStorage, network.chain.id);
        setStored(undefined);
        setAuthorized(false);
        throw new Error("This device is no longer authorized; recover the wallet before signing");
      }
      const result = await executeWalletRequest({
        chainId: activePrompt.event.params.chainId,
        request: activePrompt.event.params.request,
        account,
        device,
        wallet,
        onStatus: setStatus,
      });
      await walletConnect.current.approveRequest(activePrompt, result);
      setReturnUrl(activePrompt.peer.redirect?.universal ?? activePrompt.peer.url);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function rejectRequest(activePrompt: SessionRequestPrompt) {
    setBusy(true);
    try {
      await walletConnect.current?.rejectRequest(activePrompt);
      setReturnUrl(activePrompt.peer.redirect?.universal ?? activePrompt.peer.url);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function revokeLocalDevice() {
    if (!wallet || !account || !device || !bundlerUrl) return;
    setBusy(true);
    try {
      await wallet.removeDevice(account, device, device.address, setStatus);
      const activeSessions = walletConnect.current?.sessions() ?? [];
      await Promise.all(
        activeSessions.map((session) => walletConnect.current?.disconnect(session.topic)),
      );
      clearWalletState(window.localStorage, network.chain.id);
      setStored(undefined);
      setAuthorized(false);
      setDevice(undefined);
      setStatus("Device revoked, wallet locked, and dapp sessions disconnected");
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <p className="eyebrow">WalletConnect wallet · Demo B</p>
      <h1>zkAccount Wallet</h1>
      <p>
        Create a passkey, authorize it with Google on the passkey manager, then sign with it here.
      </p>

      <label htmlFor="network">Network</label>
      <select
        id="network"
        value={selectedNetworkKey}
        disabled={busy || sessions.length > 0 || prompt !== undefined}
        onChange={(event) => {
          window.localStorage.setItem(NETWORK_KEY, event.target.value);
          window.location.reload();
        }}
      >
        <option value="base-sepolia">Base Sepolia</option>
        <option value="ethereum-sepolia">Ethereum Sepolia</option>
      </select>
      {(sessions.length > 0 || prompt) && (
        <small>
          Disconnect active dapps and resolve pending requests before switching networks.
        </small>
      )}

      <section>
        <strong>{authorized ? "Wallet ready" : stored ? "Load wallet" : "Create a passkey"}</strong>
        {account && <span>{account}</span>}
        {account && (
          <span>
            Balance: {formatEther(balance)} {network.chain.name} ETH
          </span>
        )}
        {device && <span>Passkey device: {device.address}</span>}
        <div className="actions compact">
          {stored && (
            <button disabled={busy} onClick={() => void loadStoredWallet()}>
              Load stored wallet
            </button>
          )}
          <button
            disabled={busy}
            className="secondary"
            onClick={() => void createPasskeyAndAuthorize()}
          >
            Create passkey
          </button>
          {authorized && (
            <button disabled={busy} className="secondary" onClick={() => void refresh()}>
              Refresh
            </button>
          )}
          {authorized && (
            <button disabled={busy || !bundlerUrl} className="danger" onClick={revokeLocalDevice}>
              Revoke this device
            </button>
          )}
        </div>
      </section>

      <section>
        <strong>Connect a dapp</strong>
        <label htmlFor="pairing-uri">WalletConnect URI</label>
        <input
          id="pairing-uri"
          value={pairingUri}
          onChange={(event) => setPairingUri(event.target.value)}
          placeholder="wc:..."
        />
        <div className="actions compact">
          <button
            disabled={busy || !walletConnectReady || !pairingUri.trim()}
            onClick={() => void pair()}
          >
            Pair
          </button>
        </div>
        <small>
          AppKit can open this wallet at <code>{window.location.origin}/wc?uri=...</code>. Pairing
          may happen while locked, but approval requires the passkey.
        </small>
      </section>

      {prompt && (
        <section className={prompt.verification.isScam ? "wallet-prompt warning" : "wallet-prompt"}>
          <strong>Approval required</strong>
          <dl>
            {Object.entries(describePrompt(prompt)).map(([label, value]) => (
              <React.Fragment key={label}>
                <dt>{label}</dt>
                <dd>{value || "—"}</dd>
              </React.Fragment>
            ))}
          </dl>
          {!authorized && <small>Load the authorized passkey before approving.</small>}
          <div className="actions compact">
            <button
              disabled={busy || !authorized}
              onClick={() =>
                void (prompt.kind === "session_proposal"
                  ? approveProposal(prompt)
                  : approveRequest(prompt))
              }
            >
              Approve
            </button>
            <button
              disabled={busy}
              className="danger"
              onClick={() =>
                void (prompt.kind === "session_proposal"
                  ? rejectProposal(prompt)
                  : rejectRequest(prompt))
              }
            >
              Reject
            </button>
          </div>
        </section>
      )}

      {returnUrl && !prompt && (
        <section>
          <strong>Request complete</strong>
          <span>Return to the dapp or close this wallet tab.</span>
          <div className="actions compact">
            <a className="button-link" href={returnUrl} rel="noreferrer">
              Return to dapp
            </a>
            <button className="secondary" onClick={() => window.close()}>
              Close wallet
            </button>
          </div>
        </section>
      )}

      <section>
        <strong>Connected dapps ({sessions.length})</strong>
        {sessions.length === 0 && <span>No active WalletConnect sessions</span>}
        {sessions.map((session) => (
          <div className="session-row" key={session.topic}>
            <span>
              {session.peer.name}
              <small>{session.peer.url}</small>
            </span>
            <button
              disabled={busy}
              className="secondary"
              onClick={() => void walletConnect.current?.disconnect(session.topic)}
            >
              Disconnect
            </button>
          </div>
        ))}
      </section>

      <section>
        <strong>Status</strong>
        <span>{status}</span>
      </section>

      {!managerUrl && <small>Set VITE_PASSKEY_MANAGER_URL to the passkey manager's origin.</small>}
      {!reownProjectId && <small>Set VITE_REOWN_PROJECT_ID to enable WalletConnect.</small>}
      {!bundlerUrl && <small>Configure a {network.chain.name} EntryPoint v0.8 bundler URL.</small>}
      <footer className="legal-links">
        <a href="/privacy.html">Privacy policy</a>
      </footer>
    </main>
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

createRoot(document.getElementById("root")!).render(<App />);
