import { useEffect, useMemo, useRef, useState } from "react";
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
  AddressDisplay,
  AppShell,
  Card,
  EmptyState,
  KeyValue,
  PageIntro,
  StatusPanel,
  TechnicalDetails,
  type StatusTone,
} from "@zkaccount/ui";
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
import "@zkaccount/ui/styles.css";
import {
  resolveDemoBRoute,
  walletCompletionCopy,
  type DemoBRoute,
  type WalletCompletion,
} from "./routing";
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
    factoryDeploymentBlock: BigInt(
      (import.meta.env.VITE_BASE_SEPOLIA_FACTORY_DEPLOYMENT_BLOCK as string | undefined) ?? "0",
    ),
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
  const [completion, setCompletion] = useState<WalletCompletion>();
  const [sessions, setSessions] = useState<
    Array<{ topic: string; peer: { name: string; url: string } }>
  >([]);
  const [walletConnectReady, setWalletConnectReady] = useState(false);
  const [route, setRoute] = useState<DemoBRoute>(() => resolveDemoBRoute(window.location.pathname));

  function navigate(next: DemoBRoute) {
    window.history.pushState(null, "", next);
    setRoute(next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function completePrompt(activePrompt: WalletPrompt, outcome: WalletCompletion["outcome"]) {
    if (walletConnect.current?.hasActivePrompt()) {
      setStatus("Another WalletConnect request is ready for review.");
      return;
    }
    setCompletion({
      outcome,
      kind: activePrompt.kind,
      returnUrl: activePrompt.peer.redirect?.universal ?? activePrompt.peer.url,
    });
    navigate("/complete");
  }

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
      navigate("/wallet");
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const result = parsePasskeyAuthorizationResult(window.location.search);
    if (result) {
      window.history.replaceState(null, "", window.location.pathname);
      const pending = takePendingAuthorization();
      queueMicrotask(() => void handleAuthorizationResult(result, pending));
    } else if (initialStored) {
      // Public metadata can be checked without invoking the authenticator.
      queueMicrotask(() => void loadStoredWallet());
    }
    // The branch above must be decided from the same read of the URL that
    // strips it, so a fresh authorization result can never race the stored-
    // wallet reload for the pre-authorization state it's about to replace.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onPopState = () => setRoute(resolveDemoBRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (!reownProjectId) return;
    let disposed = false;
    void createWalletConnectController(reownProjectId, network.chain.id, {
      onPrompt: (nextPrompt) => {
        setPrompt(nextPrompt);
        if (nextPrompt) navigate("/request");
      },
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
      completePrompt(activePrompt, "approved");
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
      completePrompt(activePrompt, "rejected");
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
      completePrompt(activePrompt, "approved");
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
      completePrompt(activePrompt, "rejected");
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

  const networkControl = (
    <div className="network-control">
      <label htmlFor="wallet-network">Network</label>
      <select
        id="wallet-network"
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
    </div>
  );
  const completionCopy = completion ? walletCompletionCopy(completion) : undefined;

  return (
    <AppShell
      product="zkAccount"
      context="Passkey wallet"
      network={network.chain.name}
      currentPath={route === "/wc" ? "/connections" : route}
      onNavigate={(href) => navigate(resolveDemoBRoute(href))}
      nav={[
        { href: "/wallet", label: "Wallet" },
        { href: "/connections", label: "Connections" },
      ]}
    >
      {(route === "/" || route === "/wallet") && !authorized && (
        <div className="wallet-home">
          <Card className="hero-card">
            <div>
              <span className="eyebrow">Portable smart wallet</span>
              <h1>One account. Every app.</h1>
              <p className="muted">
                Create a passkey for this app, authorize it privately with Google, and use the same
                self-custodial account anywhere zkAccount is supported.
              </p>
              <div className="actions">
                <button
                  className="primary-button blue"
                  disabled={busy}
                  onClick={() => void createPasskeyAndAuthorize()}
                >
                  Create my passkey
                </button>
                {stored && (
                  <button
                    className="secondary-button"
                    disabled={busy}
                    onClick={() => void loadStoredWallet()}
                  >
                    Load saved wallet
                  </button>
                )}
              </div>
              <div style={{ marginTop: 20 }}>
                <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
              </div>
              <div className="config-list">
                {!managerUrl && (
                  <span className="fine-print">Passkey manager URL is not configured.</span>
                )}
                {!bundlerUrl && (
                  <span className="fine-print">EntryPoint v0.8 bundler URL is not configured.</span>
                )}
              </div>
            </div>
            <div className="wallet-orbit">
              <img src="/logo.svg" alt="zkAccount" />
            </div>
          </Card>
          <div className="grid three" style={{ marginTop: 18 }}>
            <Card title="Google recoverable" eyebrow="Identity">
              <p className="muted">Resolve the same account without exporting a seed phrase.</p>
            </Card>
            <Card title="Passkey secured" eyebrow="Every action">
              <p className="muted">Your authenticator approves each message and transaction.</p>
            </Card>
            <Card title="Private onchain" eyebrow="Zero knowledge">
              <p className="muted">Google identity is proved locally, never published.</p>
            </Card>
          </div>
        </div>
      )}

      {authorized && (route === "/wallet" || route === "/") && (
        <div className="wallet-home">
          <PageIntro
            eyebrow="Wallet ready"
            title="Your portable account."
            description="This origin’s passkey is authorized. Connect a dapp or approve a fresh user-verified signature."
            aside={networkControl}
          />
          <Card className="hero-card">
            <div>
              <span className="eyebrow">Available balance</span>
              <div className="balance">
                {formatEther(balance)} <small>ETH</small>
              </div>
              <p className="muted">{network.chain.name}</p>
              {account && <AddressDisplay label="Smart account" value={account} />}
              <div className="actions">
                <button className="primary-button blue" onClick={() => navigate("/connections")}>
                  Connect a dapp
                </button>
                <button className="secondary-button" disabled={busy} onClick={() => void refresh()}>
                  Refresh
                </button>
              </div>
            </div>
            <div className="stack">
              <Card title="Passkey active" eyebrow="Security">
                <p className="muted">Every signature opens a fresh authenticator prompt.</p>
                <span className="pill">User verified</span>
              </Card>
              <KeyValue label="Connected dapps" value={sessions.length} />
            </div>
          </Card>
          <div style={{ marginTop: 18 }}>
            <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
          </div>
          {!bundlerUrl && (
            <StatusPanel tone="warning">
              Configure an EntryPoint v0.8 bundler URL to submit onchain actions.
            </StatusPanel>
          )}
          {device && (
            <TechnicalDetails summary="Wallet security and device details">
              <KeyValue label="Passkey device" value={device.address} mono />
              <KeyValue label="RP ID" value={device.rpId} />
              <button
                className="danger-button"
                disabled={busy || !bundlerUrl}
                onClick={() => void revokeLocalDevice()}
              >
                Revoke this device
              </button>
            </TechnicalDetails>
          )}
        </div>
      )}

      {(route === "/connections" || route === "/wc") && (
        <div>
          <PageIntro
            eyebrow="WalletConnect"
            title="Connect with confidence."
            description="Pair with an existing dapp, review exactly what it requests, and approve with your passkey."
            aside={networkControl}
          />
          <div className="split">
            <Card title="Pair a dapp" eyebrow="New connection">
              <label htmlFor="pairing-uri">WalletConnect URI</label>
              <div className="pair-field">
                <input
                  id="pairing-uri"
                  value={pairingUri}
                  onChange={(event) => setPairingUri(event.target.value)}
                  placeholder="wc:…"
                />
                <button
                  className="primary-button blue"
                  disabled={busy || !walletConnectReady || !pairingUri.trim()}
                  onClick={() => void pair()}
                >
                  Pair
                </button>
              </div>
              <p className="fine-print">
                AppKit can open this wallet at <code>{window.location.origin}/wc?uri=…</code>.
                Pairing can begin while locked, but approval requires an authorized passkey.
              </p>
              <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
            </Card>
            <Card title="Active connections" eyebrow="Sessions">
              <div className="connection-count">{sessions.length}</div>
              {sessions.length === 0 ? (
                <p className="muted">No dapps are connected yet.</p>
              ) : (
                <ul className="session-list">
                  {sessions.map((session) => (
                    <li className="session-row" key={session.topic}>
                      <span>
                        <b>{session.peer.name}</b>
                        <small>{session.peer.url}</small>
                      </span>
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => void walletConnect.current?.disconnect(session.topic)}
                      >
                        Disconnect
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
          {!reownProjectId && (
            <div style={{ marginTop: 18 }}>
              <StatusPanel tone="warning">
                Set VITE_REOWN_PROJECT_ID to enable WalletConnect.
              </StatusPanel>
            </div>
          )}
        </div>
      )}

      {route === "/request" && (
        <div className="journey">
          <PageIntro
            eyebrow="Approval required"
            title="Review before signing."
            description="Confirm the dapp, origin, network, and requested method. A passkey prompt appears only after you approve."
          />
          {!prompt ? (
            <Card>
              <EmptyState
                title="No active request"
                action={
                  <button className="secondary-button" onClick={() => navigate("/connections")}>
                    View connections
                  </button>
                }
              >
                The WalletConnect request may have been completed or expired.
              </EmptyState>
            </Card>
          ) : (
            <Card
              className={prompt.verification.isScam ? "wallet-prompt warning" : "wallet-prompt"}
            >
              <div className="request-icon">↗</div>
              {prompt.verification.isScam && (
                <StatusPanel tone="error" label="Security warning">
                  WalletConnect verification marked this origin as suspicious. Reject unless you are
                  certain it is safe.
                </StatusPanel>
              )}
              <div className="prompt-grid" style={{ marginTop: 20 }}>
                {Object.entries(describePrompt(prompt)).map(([label, value]) => (
                  <KeyValue
                    key={label}
                    label={label}
                    value={value || "—"}
                    mono={label === "Origin"}
                  />
                ))}
              </div>
              {!authorized && (
                <div style={{ marginTop: 18 }}>
                  <StatusPanel tone="warning">
                    Load the authorized passkey before approving.
                  </StatusPanel>
                </div>
              )}
              <div className="actions">
                <button
                  className="primary-button blue"
                  disabled={busy || !authorized}
                  onClick={() =>
                    void (prompt.kind === "session_proposal"
                      ? approveProposal(prompt)
                      : approveRequest(prompt))
                  }
                >
                  {prompt.kind === "session_proposal" ? "Connect dapp" : "Approve with passkey"}
                </button>
                <button
                  className="danger-button"
                  disabled={busy}
                  onClick={() =>
                    void (prompt.kind === "session_proposal"
                      ? rejectProposal(prompt)
                      : rejectRequest(prompt))
                  }
                >
                  Reject
                </button>
              </div>
              <div style={{ marginTop: 18 }}>
                <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
              </div>
            </Card>
          )}
        </div>
      )}

      {route === "/complete" && (
        <div className="journey">
          <PageIntro
            eyebrow="Request complete"
            title={completionCopy?.title ?? "No completed request."}
            description={
              completionCopy?.description ??
              "Return to your connections to review a WalletConnect request."
            }
          />
          <Card className="hero-card centered">
            <div className="completion-mark" data-outcome={completion?.outcome ?? "idle"}>
              {completion ? (completion.outcome === "rejected" ? "×" : "✓") : "—"}
            </div>
            <h2>{completionCopy?.detail ?? "Nothing was approved"}</h2>
            <p className="muted">
              {completion?.outcome === "rejected"
                ? "Your wallet remains unchanged."
                : "Your account stayed in your hands."}
            </p>
            <div className="actions">
              {completion?.returnUrl && (
                <a className="primary-button blue" href={completion.returnUrl} rel="noreferrer">
                  Return to dapp
                </a>
              )}
              {!completion && (
                <button className="primary-button blue" onClick={() => navigate("/connections")}>
                  View connections
                </button>
              )}
              <button className="secondary-button" onClick={() => window.close()}>
                Close wallet
              </button>
            </div>
            <TechnicalDetails summary="View completion status">
              <StatusPanel tone={statusTone(status, false)}>{status}</StatusPanel>
            </TechnicalDetails>
          </Card>
        </div>
      )}
    </AppShell>
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function statusTone(message: string, busy: boolean): StatusTone {
  if (busy) return "busy";
  const lower = message.toLowerCase();
  if (/(fail|error|reject|expired|no stored|not found)/.test(lower)) return "error";
  if (/(configure|required|need|locked)/.test(lower)) return "warning";
  if (/(ready|authorized|connected|complete|completed)/.test(lower)) return "success";
  return "idle";
}

createRoot(document.getElementById("root")!).render(<App />);
