import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { formatEther, zeroAddress, type Address, type Hex } from "viem";
import { baseSepolia, sepolia } from "viem/chains";
import {
  Google4337Client,
  createPasskeyDeviceKey,
  googleIdentityCommitment,
  loadPasskeyDeviceKey,
  loginWithGoogle,
  proveGoogleAuthorization,
  warmGoogleProver,
  createPasskeyResultUrl,
  parsePasskeyAuthorizationRequest,
  GOOGLE_ACTION_VIEW,
  GOOGLE_ACTION_REMOVE_DEVICE,
  type AuthorizedDevice,
  type PasskeyAuthorizationRequest,
  type DeviceKey,
  type GoogleLoginResult,
  type GoogleProof,
} from "@zkaccount/sdk";
import "./style.css";

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
const passkeyOptions = { scope: "demo-a", displayName: "zkAccount Demo A" };
const passkeyStorageKey = `zkaccount.demo-a.passkey.v1.${network.chain.id}`;

function App() {
  const button = useRef<HTMLDivElement>(null);
  const dashboardButton = useRef<HTMLDivElement>(null);
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
  const [status, setStatus] = useState("Ready");
  const [login, setLogin] = useState<GoogleLoginResult>();
  const [proof, setProof] = useState<GoogleProof>();
  const [device, setDevice] = useState<DeviceKey>();
  const [account, setAccount] = useState<Address>();
  const [balance, setBalance] = useState(0n);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [request, setRequest] = useState<PasskeyAuthorizationRequest>();
  const [returnUrl, setReturnUrl] = useState<string>();
  const [dashboardStatus, setDashboardStatus] = useState("");
  const [dashboardBusy, setDashboardBusy] = useState(false);
  const [dashboardAccount, setDashboardAccount] = useState<Address>();
  const [dashboardDevices, setDashboardDevices] = useState<AuthorizedDevice[]>([]);
  const [revokingDevice, setRevokingDevice] = useState<Address>();

  useEffect(() => {
    void parsePasskeyAuthorizationRequest(
      window.location.search,
      Object.values(networks).map((item) => item.chain.id),
    )
      .then(setRequest)
      .catch((error: unknown) => {
        if (window.location.search)
          setStatus(error instanceof Error ? error.message : String(error));
      });
  }, []);

  async function approveRequest() {
    if (!request) return;
    const requestedDevice = { ...request.device, credentialId: "0x" as `0x${string}` };
    setDevice(requestedDevice);
    await start(requestedDevice);
  }

  function rejectRequest() {
    if (!request) return;
    setReturnUrl(
      createPasskeyResultUrl(request.callback, {
        status: "rejected",
        state: request.state,
        chainId: request.chainId,
      }).toString(),
    );
  }

  async function loadPasskey(create: boolean) {
    setBusy(true);
    setStatus(create ? "Creating Demo A passkey" : "Loading stored passkey metadata");
    try {
      const nextDevice = create
        ? await createPasskeyDeviceKey(passkeyOptions)
        : loadStoredPasskey();
      if (create) window.localStorage.setItem(passkeyStorageKey, JSON.stringify(nextDevice));
      setDevice(nextDevice);
      setLogin(undefined);
      setProof(undefined);
      setAccount(undefined);
      setBalance(0n);
      setAuthorized(false);
      setStatus("Passkey ready. Choose Continue with Google to resolve the smart account.");
      await start(nextDevice);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
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
    setStatus(
      nextAuthorized ? "Local device is authorized" : "Account needs Google device authorization",
    );
  }

  async function start(localDevice: DeviceKey) {
    if (!button.current || !clientId || !factory || !wallet) {
      setStatus("Set VITE_GOOGLE_CLIENT_ID and VITE_ACCOUNT_FACTORY first");
      return;
    }
    setBusy(true);
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
        button: button.current,
        device: localDevice,
      });
      setLogin(result);
      setDevice(result.device);
      setStatus("Checking whether this device is already authorized");
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
        setStatus("Local device is already authorized. No Google proof is needed.");
        return;
      }
      setStatus("Device authorization is required. Warming up the prover");
      await warmGoogleProver();
      setStatus("Generating proof in this browser");
      const generatedProof = await proveGoogleAuthorization(result);
      setProof(generatedProof);
      setStatus(
        bundlerUrl
          ? `Proof ready. Fund ${predicted} if needed, then authorize this device.`
          : `Proof ready. Configure VITE_BUNDLER_URL to submit the UserOperation.`,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setStatus(message);
      if (request) {
        setReturnUrl(
          createPasskeyResultUrl(request.callback, {
            status: "failed",
            state: request.state,
            chainId: request.chainId,
            error: "authentication_failed",
          }).toString(),
        );
      }
    } finally {
      setBusy(false);
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
      await refresh(result.accountAddress, device);
      if (request)
        setReturnUrl(
          createPasskeyResultUrl(request.callback, {
            status: "approved",
            state: request.state,
            chainId: request.chainId,
            account: result.accountAddress,
            device: request.device.address,
          }).toString(),
        );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setStatus(message);
      if (request) {
        setReturnUrl(
          createPasskeyResultUrl(request.callback, {
            status: "failed",
            state: request.state,
            chainId: request.chainId,
            error: "authorization_failed",
          }).toString(),
        );
      }
    } finally {
      setBusy(false);
    }
  }

  async function sendSelfTransaction() {
    if (!wallet || !account || !device || !bundlerUrl) return;
    setBusy(true);
    try {
      await wallet.sendTransaction(account, device, { to: account }, setStatus);
      await refresh(account, device);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function revokeLocalDevice() {
    if (!wallet || !account || !device || !bundlerUrl) return;
    setBusy(true);
    try {
      await wallet.removeDevice(account, device, device.address, setStatus);
      await refresh(account, device);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function lookupAccount() {
    if (!dashboardButton.current || !clientId || !factory || !wallet) {
      setDashboardStatus("Set VITE_GOOGLE_CLIENT_ID and VITE_ACCOUNT_FACTORY first");
      return;
    }
    setDashboardBusy(true);
    setDashboardStatus("Authenticating with Google");
    setDashboardAccount(undefined);
    setDashboardDevices([]);
    try {
      const login = await loginWithGoogle({
        clientId,
        factory,
        chainId: network.chain.id,
        button: dashboardButton.current,
        device: placeholderDevice(zeroAddress),
        action: GOOGLE_ACTION_VIEW,
      });
      const identity = await googleIdentityCommitment(login.claims);
      const predicted = await wallet.getAccountAddress(identity);
      setDashboardAccount(predicted);
      setDashboardStatus("Loading authorized devices");
      const devices = await wallet.listAuthorizedDevices(predicted);
      setDashboardDevices(devices);
      setDashboardStatus(
        devices.length
          ? `Found ${devices.length} authorized device${devices.length === 1 ? "" : "s"}.`
          : "No authorized devices found for this account.",
      );
    } catch (error) {
      setDashboardStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setDashboardBusy(false);
    }
  }

  async function revokeDashboardDevice(target: Address) {
    if (!dashboardButton.current || !clientId || !factory || !wallet || !dashboardAccount) {
      setDashboardStatus("Look up the account with Google first");
      return;
    }
    if (!bundlerUrl) {
      setDashboardStatus("Configure VITE_BUNDLER_URL to submit a revocation");
      return;
    }
    setDashboardBusy(true);
    setRevokingDevice(target);
    setDashboardStatus("Authenticating with Google to authorize revocation");
    try {
      const login = await loginWithGoogle({
        clientId,
        factory,
        chainId: network.chain.id,
        button: dashboardButton.current,
        device: placeholderDevice(target),
        action: GOOGLE_ACTION_REMOVE_DEVICE,
      });
      setDashboardStatus("Generating proof in this browser");
      await warmGoogleProver();
      const proof = await proveGoogleAuthorization(login);
      setDashboardStatus("Submitting revocation");
      await wallet.revokeDeviceWithGoogle(proof, target, setDashboardStatus);
      const devices = await wallet.listAuthorizedDevices(dashboardAccount);
      setDashboardDevices(devices);
      setDashboardStatus(`Revoked device ${target}.`);
    } catch (error) {
      setDashboardStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setDashboardBusy(false);
      setRevokingDevice(undefined);
    }
  }

  return (
    <main>
      <p className="eyebrow">Independent origin · Demo A</p>
      <h1>Google → ERC-4337</h1>
      <p>
        Authenticate, prove the Google credential locally, then authorize this origin's passkey.
      </p>
      <label htmlFor="network">Network</label>
      <select
        id="network"
        value={selectedNetworkKey}
        onChange={(event) => {
          window.localStorage.setItem(NETWORK_KEY, event.target.value);
          window.location.reload();
        }}
      >
        <option value="base-sepolia">Base Sepolia</option>
        <option value="ethereum-sepolia">Ethereum Sepolia</option>
      </select>
      <div className="actions">
        {request && (
          <button disabled={busy} onClick={() => void approveRequest()}>
            Approve requested passkey
          </button>
        )}
        <button disabled={busy} onClick={() => void loadPasskey(false)}>
          Load stored passkey
        </button>
        <button disabled={busy} className="secondary" onClick={() => void loadPasskey(true)}>
          Create passkey
        </button>
        {proof && !authorized && (
          <button disabled={busy || !bundlerUrl} onClick={authorizeDevice}>
            Deploy / authorize device
          </button>
        )}
        {account && (
          <button disabled={busy} className="secondary" onClick={() => void refresh()}>
            Refresh account
          </button>
        )}
        {authorized && (
          <button disabled={busy || !bundlerUrl} onClick={sendSelfTransaction}>
            Send 0 ETH self-transaction
          </button>
        )}
        {authorized && (
          <button disabled={busy || !bundlerUrl} className="danger" onClick={revokeLocalDevice}>
            Revoke this device
          </button>
        )}
      </div>
      <div ref={button} className={`google-button${device ? " visible" : ""}`} />
      <section>
        <strong>Status</strong>
        <span>{status}</span>
      </section>
      {request && (
        <section>
          <strong>Incoming passkey request</strong>
          <span>RP ID: {request.rpId}</span>
          <span>Callback: {request.callback.host}</span>
          <span>Device: {request.device.address}</span>
          <span>Chain: {request.chainId}</span>
          <small>Review this request before continuing with Google.</small>
          <div className="actions compact">
            <button disabled={busy} className="danger" onClick={rejectRequest}>
              Reject
            </button>
          </div>
        </section>
      )}
      {returnUrl && (
        <section>
          <strong>Request complete</strong>
          <a className="button-link" href={returnUrl}>
            Return to requesting app
          </a>
        </section>
      )}
      {account && (
        <section>
          <strong>Smart account</strong>
          <span>{account}</span>
          <span>
            Balance: {formatEther(balance)} {network.chain.name} ETH
          </span>
          <span>Passkey device: {device?.address ?? "Create or load a passkey"}</span>
          {device && <span>Key protection: native WebAuthn P-256 credential</span>}
          <span>Authorized: {authorized ? "yes" : "no"}</span>
        </section>
      )}
      {login && (
        <section>
          <strong>Development claims (never the full JWT)</strong>
          <span>Issuer: {login.claims.iss}</span>
          <span>Audience: {login.claims.aud}</span>
          <span>Subject identifier (circuit input): {login.claims.sub}</span>
          <span>Expires: {new Date(login.claims.exp * 1000).toISOString()}</span>
          <span>Nonce matched: yes</span>
        </section>
      )}
      {proof && (
        <section>
          <strong>Private proof</strong>
          <span>Identity commitment: {proof.publicInputs[0]}</span>
          <span>Proof size: {(proof.proof.length - 2) / 2} bytes</span>
          <span>Google subject remains private</span>
        </section>
      )}
      {!bundlerUrl && (
        <small>
          Configure the {network.chain.name} ERC-4337 bundler URL with EntryPoint v0.8 support.
          Account prediction and proof generation work without it.
        </small>
      )}
      <small>
        Only public credential metadata is stored. Every transaction or message signature requires a
        fresh user-verified WebAuthn assertion.
      </small>

      <section>
        <strong>Manage devices with Google</strong>
        <p>
          Resolve any account with Google, review its authorized devices by cleartext RP ID, and
          revoke one with a fresh Google authorization. No local passkey is required.
        </p>
        <div className="actions">
          <button disabled={dashboardBusy} onClick={() => void lookupAccount()}>
            Look up account
          </button>
        </div>
        <div ref={dashboardButton} className={`google-button${dashboardBusy ? " visible" : ""}`} />
        {dashboardStatus && <span>{dashboardStatus}</span>}
        {dashboardAccount && <span>Account: {dashboardAccount}</span>}
        {dashboardAccount && dashboardDevices.length > 0 && (
          <ul className="device-list">
            {dashboardDevices.map((authorizedDevice) => (
              <li key={authorizedDevice.address}>
                <span>{authorizedDevice.rpId}</span>
                <small>{authorizedDevice.address}</small>
                <button
                  disabled={dashboardBusy || !bundlerUrl}
                  className="danger"
                  onClick={() => void revokeDashboardDevice(authorizedDevice.address)}
                >
                  {revokingDevice === authorizedDevice.address ? "Revoking…" : "Revoke via Google"}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <footer className="legal-links">
        <a href="/privacy.html">Privacy policy</a>
      </footer>
    </main>
  );
}

function placeholderDevice(address: Address): DeviceKey {
  return {
    address,
    credentialId: "0x" as Hex,
    publicKeyX: `0x${"00".repeat(32)}` as Hex,
    publicKeyY: `0x${"00".repeat(32)}` as Hex,
    rpId: "",
    rpIdHash: `0x${"00".repeat(32)}` as Hex,
  };
}

function loadStoredPasskey(): DeviceKey {
  const encoded = window.localStorage.getItem(passkeyStorageKey);
  if (!encoded) throw new Error("No stored passkey metadata was found; create a new passkey");
  try {
    return loadPasskeyDeviceKey(JSON.parse(encoded));
  } catch (error) {
    window.localStorage.removeItem(passkeyStorageKey);
    throw error;
  }
}

createRoot(document.getElementById("root")!).render(<App />);
