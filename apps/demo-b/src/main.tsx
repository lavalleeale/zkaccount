import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { formatEther, type Address } from "viem";
import { baseSepolia, sepolia } from "viem/chains";
import {
  Google4337Client,
  createPasskeyDeviceKey,
  googleIdentityCommitment,
  loginWithGoogle,
  proveGoogleAuthorization,
  unlockPasskeyDeviceKey,
  warmGoogleProver,
  type DeviceKey,
  type GoogleLoginResult,
  type GoogleProof,
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

const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;
const NETWORK_KEY = "zkaccount.selected-network";
const networks = {
  "base-sepolia": {
    chain: baseSepolia,
    factory: (import.meta.env.VITE_BASE_SEPOLIA_FACTORY ?? import.meta.env.VITE_ACCOUNT_FACTORY) as
      Address | undefined,
    rpcUrl: (import.meta.env.VITE_BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org") as string,
    bundlerUrl: (import.meta.env.VITE_BASE_SEPOLIA_BUNDLER_URL ??
      import.meta.env.VITE_BUNDLER_URL) as string | undefined,
    factoryDeploymentBlock: 45_965_274n,
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

function App() {
  const googleButton = useRef<HTMLDivElement>(null);
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
    initialStored ? "Known smart account is locked. Unlock its passkey to continue." : "Ready",
  );
  const [login, setLogin] = useState<GoogleLoginResult>();
  const [proof, setProof] = useState<GoogleProof>();
  const [device, setDevice] = useState<DeviceKey>();
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

  async function loadPasskey(create: boolean) {
    setBusy(true);
    setStatus(create ? "Creating Demo B passkey" : "Unlocking Demo B passkey");
    try {
      const nextDevice = create
        ? await createPasskeyDeviceKey(passkeyOptions)
        : await unlockPasskeyDeviceKey(passkeyOptions);
      setDevice(nextDevice);
      setLogin(undefined);
      setProof(undefined);

      if (!create && stored && wallet) {
        setStatus("Checking the stored smart account authorization");
        const stillAuthorized = await wallet.isDeviceAuthorized(stored.account, nextDevice.address);
        if (stillAuthorized) {
          setAccount(stored.account);
          setAuthorized(true);
          setBalance(await wallet.getBalance(stored.account));
          setStatus("Wallet unlocked. Review any pending dapp request.");
          return;
        }
        clearWalletState(window.localStorage, network.chain.id);
        setStored(undefined);
        setStatus("This passkey is no longer authorized. Recover the account with Google.");
      }

      setAccount(undefined);
      setBalance(0n);
      setAuthorized(false);
      await start(nextDevice);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function refresh(address = account, localDevice = device) {
    if (!wallet || !address || !localDevice) return;
    const [nextBalance, nextAuthorized] = await Promise.all([
      wallet.getBalance(address),
      wallet.isDeviceAuthorized(address, localDevice.address),
    ]);
    setBalance(nextBalance);
    setAuthorized(nextAuthorized);
    if (!nextAuthorized) {
      clearWalletState(window.localStorage, network.chain.id);
      setStored(undefined);
    }
    setStatus(
      nextAuthorized ? "Wallet is unlocked and ready" : "This device needs Google authorization",
    );
  }

  async function start(localDevice: DeviceKey) {
    if (!googleButton.current || !clientId || !factory || !wallet) {
      setStatus("Set VITE_GOOGLE_CLIENT_ID and VITE_ACCOUNT_FACTORY first");
      return;
    }
    setAccount(undefined);
    setBalance(0n);
    setProof(undefined);
    setAuthorized(false);
    setStatus("Authenticating with Google");
    try {
      const result = await loginWithGoogle({
        clientId,
        factory,
        chainId: network.chain.id,
        button: googleButton.current,
        device: localDevice,
      });
      setLogin(result);
      setDevice(result.device);
      setStatus("Resolving the portable smart account");
      const identity = await googleIdentityCommitment(result.claims);
      const predicted = await wallet.getAccountAddress(identity);
      const [nextBalance, nextAuthorized] = await Promise.all([
        wallet.getBalance(predicted),
        wallet.isDeviceAuthorized(predicted, result.device.address),
      ]);
      setAccount(predicted);
      setBalance(nextBalance);
      setAuthorized(nextAuthorized);
      if (nextAuthorized) {
        persistAccount(predicted);
        setStatus("Wallet recovered and unlocked. Review any pending dapp request.");
        return;
      }
      setStatus("Device authorization is required. Warming up the prover");
      await warmGoogleProver();
      setStatus("Generating proof in this independent origin");
      const generatedProof = await proveGoogleAuthorization(result);
      setProof(generatedProof);
      setStatus(
        bundlerUrl
          ? `Authorize this passkey on ${predicted} before using it as a wallet.`
          : "Configure VITE_BUNDLER_URL to submit the authorization UserOperation.",
      );
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function authorizeDevice() {
    if (!wallet || !proof || !device || !bundlerUrl) {
      setStatus("A proof and VITE_BUNDLER_URL are required");
      return;
    }
    setBusy(true);
    try {
      const result = await wallet.authorizeDevice(proof, device, setStatus);
      setAccount(result.accountAddress);
      persistAccount(result.accountAddress);
      await refresh(result.accountAddress, device);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
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
      setStatus("Unlock and authorize the passkey before connecting");
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
      setStatus("Unlock the authorized passkey before approving this request");
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
      const sessions = walletConnect.current?.sessions() ?? [];
      await Promise.all(
        sessions.map((session) => walletConnect.current?.disconnect(session.topic)),
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

  function persistAccount(address: Address) {
    if (!factory) return;
    setStored(saveWalletState(window.localStorage, factory, address, network.chain.id));
  }

  return (
    <main>
      <p className="eyebrow">WalletConnect wallet · Demo B</p>
      <h1>zkAccount Wallet</h1>
      <p>Recover with Google, unlock with a passkey, and approve requests from AppKit dapps.</p>

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
        <strong>
          {authorized ? "Wallet unlocked" : stored ? "Wallet locked" : "Recover wallet"}
        </strong>
        {account && <span>{account}</span>}
        {account && (
          <span>
            Balance: {formatEther(balance)} {network.chain.name} ETH
          </span>
        )}
        {device && <span>Passkey device: {device.address}</span>}
        <div className="actions compact">
          <button disabled={busy} onClick={() => void loadPasskey(false)}>
            Unlock passkey
          </button>
          {!stored && (
            <button disabled={busy} className="secondary" onClick={() => void loadPasskey(true)}>
              Create passkey
            </button>
          )}
          {proof && !authorized && (
            <button disabled={busy || !bundlerUrl} onClick={() => void authorizeDevice()}>
              Authorize wallet device
            </button>
          )}
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
        <div
          ref={googleButton}
          className={`google-button${device && !authorized ? " visible" : ""}`}
        />
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
          {!authorized && <small>Unlock the authorized passkey before approving.</small>}
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

      {login && (
        <section>
          <strong>Recovery authentication</strong>
          <span>Audience: {login.claims.aud}</span>
          <span>Nonce matched: yes</span>
        </section>
      )}
      {proof && (
        <section>
          <strong>Private recovery proof</strong>
          <span>Identity commitment: {proof.publicInputs[0]}</span>
          <span>Proof size: {(proof.proof.length - 2) / 2} bytes</span>
        </section>
      )}
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
