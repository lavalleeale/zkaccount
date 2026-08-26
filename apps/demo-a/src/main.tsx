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
  type AuthorizedDevice,
  type PasskeyAuthorizationRequest,
  type DeviceKey,
  type GoogleClaims,
  type GoogleLoginResult,
  type GoogleProof,
  type PendingDeviceInfo,
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
const requestedChainId = Number(new URLSearchParams(window.location.search).get("chainId"));
const requestedNetworkKey = (Object.keys(networks) as NetworkKey[]).find(
  (key) => networks[key].chain.id === requestedChainId,
);
const selectedNetworkKey: NetworkKey =
  requestedNetworkKey ??
  (window.localStorage.getItem(NETWORK_KEY) === "ethereum-sepolia"
    ? "ethereum-sepolia"
    : "base-sepolia");
const network = networks[selectedNetworkKey];
const { factory, rpcUrl, bundlerUrl } = network;
const passkeyOptions = { scope: "demo-a", displayName: "zkAccount Demo A" };
const passkeyStorageKey = `zkaccount.demo-a.passkey.v1.${network.chain.id}`;
const authorizedDevicesStorageKey = `zkaccount.demo-a.authorized-devices.v1.${network.chain.id}`;
const googleSubStorageKey = "zkaccount.demo-a.google-sub.v1";

/** The identity commitment only depends on `iss`/`sub`, so a cached subject
 * lets us re-derive it without asking the user to sign in with Google again. */
function loadCachedGoogleSub(): string | undefined {
  return window.localStorage.getItem(googleSubStorageKey) ?? undefined;
}

function storeCachedGoogleSub(sub: string): void {
  window.localStorage.setItem(googleSubStorageKey, sub);
}

function claimsForCachedSub(sub: string): GoogleClaims {
  return { iss: "https://accounts.google.com", aud: "", sub, iat: 0, exp: 0 };
}

interface StoredAuthorizedDevice {
  account: Address;
  device: DeviceKey;
}

interface PendingDeviceState {
  account: Address;
  device: Address;
  readyAt: number;
}

/** Remembers a device this browser has seen become active on an account, so a
 * later Google-authorized addition that gets queued behind the timelock can
 * be approved instantly from here instead of waiting it out. */
function rememberAuthorizedDevice(account: Address, authorizedDevice: DeviceKey): void {
  const list = loadAuthorizedDevices().filter(
    (entry) => !(entry.account === account && entry.device.address === authorizedDevice.address),
  );
  list.push({ account, device: authorizedDevice });
  window.localStorage.setItem(authorizedDevicesStorageKey, JSON.stringify(list.slice(-20)));
}

function forgetAuthorizedDevice(account: Address, deviceAddress: Address): void {
  const list = loadAuthorizedDevices().filter(
    (entry) => !(entry.account === account && entry.device.address === deviceAddress),
  );
  window.localStorage.setItem(authorizedDevicesStorageKey, JSON.stringify(list));
}

function loadAuthorizedDevices(): StoredAuthorizedDevice[] {
  const raw = window.localStorage.getItem(authorizedDevicesStorageKey);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? (parsed as StoredAuthorizedDevice[]) : [];
  } catch {
    return [];
  }
}

/** Finds a locally known, already-authorized device for `account` other than
 * `excludeDevice`, to use as the approver for a queued device. */
function findApproverDevice(account: Address, excludeDevice: Address): DeviceKey | undefined {
  const match = loadAuthorizedDevices().find(
    (entry) => entry.account === account && entry.device.address !== excludeDevice,
  );
  if (!match) return undefined;
  try {
    return loadPasskeyDeviceKey(match.device);
  } catch {
    return undefined;
  }
}

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
  const [pendingDevice, setPendingDevice] = useState<PendingDeviceState>();
  const [dashboardStatus, setDashboardStatus] = useState("");
  const [dashboardBusy, setDashboardBusy] = useState(false);
  const [dashboardAccount, setDashboardAccount] = useState<Address>();
  const [dashboardDevices, setDashboardDevices] = useState<AuthorizedDevice[]>([]);
  const [revokingDevice, setRevokingDevice] = useState<Address>();
  const [dashboardPendingDevices, setDashboardPendingDevices] = useState<PendingDeviceInfo[]>([]);
  const [resolvingPendingDevice, setResolvingPendingDevice] = useState<Address>();
  const [signingIn, setSigningIn] = useState(false);

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
    if (nextAuthorized) rememberAuthorizedDevice(address, localDevice);
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
    setLogin(undefined);
    try {
      const cachedSub = loadCachedGoogleSub();
      if (cachedSub) {
        setStatus("Checking cached Google identity");
        const identity = await googleIdentityCommitment(claimsForCachedSub(cachedSub));
        const predicted = await wallet.getAccountAddress(identity);
        const [nextBalance, nextAuthorized] = await Promise.all([
          wallet.getBalance(predicted),
          wallet.isDeviceAuthorized(predicted, localDevice.address),
        ]);
        if (nextAuthorized) {
          setAccount(predicted);
          setBalance(nextBalance);
          setAuthorized(true);
          rememberAuthorizedDevice(predicted, localDevice);
          setStatus("Local device is authorized (used the cached Google identity, no sign-in needed).");
          return;
        }
      }
      setStatus("Authenticating with Google");
      setSigningIn(true);
      const result = await loginWithGoogle({
        clientId,
        factory,
        chainId: network.chain.id,
        button: button.current,
        device: localDevice,
      });
      setLogin(result);
      setDevice(result.device);
      storeCachedGoogleSub(result.claims.sub);
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
        rememberAuthorizedDevice(predicted, result.device);
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
      setSigningIn(false);
    }
  }

  async function authorizeDevice() {
    if (!wallet || !proof || !device || !bundlerUrl) {
      setStatus("A proof and VITE_BUNDLER_URL are required");
      return;
    }
    setBusy(true);
    setPendingDevice(undefined);
    try {
      const result = await wallet.authorizeDevice(proof, device, setStatus);
      setAccount(result.accountAddress);
      await refresh(result.accountAddress, device);
      if (result.pending) {
        setPendingDevice({
          account: result.accountAddress,
          device: device.address,
          readyAt: result.pending.readyAt,
        });
        setStatus(
          `Device queued behind a security delay, ready at ${new Date(result.pending.readyAt * 1000).toLocaleString()}. ` +
            "Approve it instantly below with another authorized device, or wait it out.",
        );
        return;
      }
      rememberAuthorizedDevice(result.accountAddress, device);
      returnToRequestingApp(result.accountAddress, device.address);
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

  function returnToRequestingApp(accountAddress: Address, deviceAddress: Address) {
    if (!request) return;
    setReturnUrl(
      createPasskeyResultUrl(request.callback, {
        status: "approved",
        state: request.state,
        chainId: request.chainId,
        account: accountAddress,
        device: deviceAddress,
      }).toString(),
    );
  }

  /** Finds a device to approve `pending` with: first the cache of devices
   * this browser has already confirmed authorized, then falling back to
   * whatever passkey is saved for this origin (checking it's actually
   * authorized on-chain, since a saved passkey may predate this account or
   * have since been revoked). */
  async function resolveApproverDevice(
    account: Address,
    deviceAddress: Address,
  ): Promise<DeviceKey | undefined> {
    if (!wallet) return undefined;
    const cached = findApproverDevice(account, deviceAddress);
    if (cached) {
      if (await wallet.isDeviceAuthorized(account, cached.address)) return cached;
      forgetAuthorizedDevice(account, cached.address);
    }
    let stored: DeviceKey;
    try {
      stored = loadStoredPasskey();
    } catch {
      return undefined;
    }
    if (stored.address === deviceAddress) return undefined;
    if (!(await wallet.isDeviceAuthorized(account, stored.address))) return undefined;
    rememberAuthorizedDevice(account, stored);
    return stored;
  }

  async function approvePendingDeviceNow() {
    if (!wallet || !pendingDevice || !device) return;
    setStatus("Checking for a known authorized device");
    const approver = await resolveApproverDevice(pendingDevice.account, pendingDevice.device);
    if (!approver) {
      setStatus(
        "No other authorized device was found in this browser (checked the approval cache and " +
          "the saved passkey). Open Demo A on a device that's already authorized to approve it, " +
          "or wait for the delay.",
      );
      return;
    }
    setBusy(true);
    try {
      await wallet.approveDevice(
        pendingDevice.account,
        approver,
        pendingDevice.device,
        setStatus,
      );
      rememberAuthorizedDevice(pendingDevice.account, device);
      await refresh(pendingDevice.account, device);
      setPendingDevice(undefined);
      setStatus("Device approved. It's active now.");
      returnToRequestingApp(pendingDevice.account, pendingDevice.device);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
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

  async function revokeAllLocalDevices() {
    if (!wallet || !account || !device || !bundlerUrl) return;
    if (
      !window.confirm(
        "Revoke every device authorized on this account in one transaction? " +
          "You will need a fresh Google sign-in to add a device again.",
      )
    )
      return;
    setBusy(true);
    try {
      const authorizedDevices = await wallet.listAuthorizedDevices(account);
      await wallet.removeAllDevices(
        account,
        device,
        authorizedDevices.map((authorizedDevice) => authorizedDevice.address),
        setStatus,
      );
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
    setDashboardPendingDevices([]);
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
      const [devices, pendingDevices] = await Promise.all([
        wallet.listAuthorizedDevices(predicted),
        wallet.listPendingDevices(predicted),
      ]);
      setDashboardDevices(devices);
      setDashboardPendingDevices(pendingDevices);
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

  async function refreshDashboardDevices(account: Address) {
    if (!wallet) return;
    const [devices, pendingDevices] = await Promise.all([
      wallet.listAuthorizedDevices(account),
      wallet.listPendingDevices(account),
    ]);
    setDashboardDevices(devices);
    setDashboardPendingDevices(pendingDevices);
  }

  async function resolvePendingDashboardDevice(target: Address, action: "approve" | "reject") {
    if (!wallet || !dashboardAccount) return;
    setResolvingPendingDevice(target);
    setDashboardStatus("Checking for a known authorized device");
    try {
      const approver = await resolveApproverDevice(dashboardAccount, target);
      if (!approver) {
        setDashboardStatus(
          "No authorized device was found in this browser (checked the approval cache and the " +
            "saved passkey). Open Demo A on a device that's already authorized on this account to " +
            `${action} it.`,
        );
        return;
      }
      setDashboardBusy(true);
      if (action === "approve") {
        await wallet.approveDevice(dashboardAccount, approver, target, setDashboardStatus);
        setDashboardStatus("Device approved. It's active now.");
      } else {
        await wallet.cancelPendingDevice(dashboardAccount, approver, target, setDashboardStatus);
        setDashboardStatus("Pending device rejected.");
      }
      await refreshDashboardDevices(dashboardAccount);
    } catch (error) {
      setDashboardStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setDashboardBusy(false);
      setResolvingPendingDevice(undefined);
    }
  }

  async function revokeDashboardDevice(target: Address) {
    if (!wallet || !dashboardAccount) {
      setDashboardStatus("Look up the account with Google first");
      return;
    }
    if (!bundlerUrl) {
      setDashboardStatus("Configure VITE_BUNDLER_URL to submit a revocation");
      return;
    }
    setDashboardBusy(true);
    setRevokingDevice(target);
    try {
      const approver = await resolveApproverDevice(dashboardAccount, target);
      if (!approver) {
        setDashboardStatus(
          "No other authorized device was found in this browser (checked the approval cache and " +
            "the saved passkey). Open Demo A on a device that's already authorized on this account " +
            "to revoke it.",
        );
        return;
      }
      await wallet.removeDevice(dashboardAccount, approver, target, setDashboardStatus);
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

  async function revokeAllDashboardDevices() {
    if (!wallet || !dashboardAccount) {
      setDashboardStatus("Look up the account with Google first");
      return;
    }
    if (!bundlerUrl) {
      setDashboardStatus("Configure VITE_BUNDLER_URL to submit a revocation");
      return;
    }
    const targets = dashboardDevices.map((authorizedDevice) => authorizedDevice.address);
    if (targets.length === 0) return;
    if (
      !window.confirm(
        `Revoke all ${targets.length} authorized device${targets.length === 1 ? "" : "s"}? ` +
          "This cannot be undone.",
      )
    )
      return;
    setDashboardBusy(true);
    try {
      // No single target to exclude here (unlike the single-device revoke), so
      // any authorized device in this browser can serve as the approver.
      const approver = await resolveApproverDevice(dashboardAccount, zeroAddress);
      if (!approver) {
        setDashboardStatus(
          "No authorized device was found in this browser to authorize the revocation.",
        );
        return;
      }
      await wallet.removeAllDevices(dashboardAccount, approver, targets, setDashboardStatus);
      setDashboardStatus(`Revoked ${targets.length} device${targets.length === 1 ? "" : "s"}.`);
    } catch (error) {
      setDashboardStatus(error instanceof Error ? error.message : String(error));
    } finally {
      const devices = await wallet.listAuthorizedDevices(dashboardAccount);
      setDashboardDevices(devices);
      setDashboardBusy(false);
      setRevokingDevice(undefined);
    }
  }

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <span className="wordmark">
            <span className="wordmark-mark">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M6 7h12l-7 10h7"
                  stroke="#7c9cf0"
                  strokeWidth="2.4"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            zkAccount
          </span>
          <span className="network-pill">
            <span className="dot" />
            {network.chain.name}
          </span>
        </div>
      </header>
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
        disabled={requestedNetworkKey !== undefined}
        onChange={(event) => {
          window.localStorage.setItem(NETWORK_KEY, event.target.value);
          window.location.reload();
        }}
      >
        <option value="base-sepolia">Base Sepolia</option>
        <option value="ethereum-sepolia">Ethereum Sepolia</option>
      </select>
      {requestedNetworkKey !== undefined && (
        <small>Network is set by the requesting app's chain ID and can't be changed here.</small>
      )}
      <div className="actions">
        {request && !returnUrl && (
          <button disabled={busy} onClick={() => void approveRequest()}>
            Approve requested passkey
          </button>
        )}
        {!request && (
          <>
            <button disabled={busy} onClick={() => void loadPasskey(false)}>
              Load stored passkey
            </button>
            <button disabled={busy} className="secondary" onClick={() => void loadPasskey(true)}>
              Create passkey
            </button>
          </>
        )}
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
        {authorized && (
          <button disabled={busy || !bundlerUrl} className="danger" onClick={() => void revokeAllLocalDevices()}>
            Revoke all devices
          </button>
        )}
      </div>
      <div ref={button} className={`google-button${signingIn ? " visible" : ""}`} />
      <div className="status-banner" data-tone={statusTone(status, busy)}>
        <span className="status-icon" />
        <div className="status-banner-body">
          <strong>Status</strong>
          <span>{status}</span>
        </div>
      </div>
      {request && (
        <section>
          <strong>Incoming passkey request</strong>
          <span>RP ID: {request.rpId}</span>
          <span>Callback: {request.callback.host}</span>
          <span>Device: {request.device.address}</span>
          <span>Chain: {request.chainId}</span>
          <small>Review this request before continuing with Google.</small>
          {!returnUrl && (
            <div className="actions compact">
              <button disabled={busy} className="danger" onClick={rejectRequest}>
                Reject
              </button>
            </div>
          )}
        </section>
      )}
      {pendingDevice && !returnUrl && (
        <section>
          <strong>Device queued</strong>
          <span>
            Ready at {new Date(pendingDevice.readyAt * 1000).toLocaleString()} unless approved
            sooner.
          </span>
          <small>
            This device was authorized by Google but the account already has another device to
            protect, so it's queued behind a security delay. An already-authorized device can
            approve it instantly instead of waiting.
          </small>
          <div className="actions compact">
            <button disabled={busy || !bundlerUrl} onClick={() => void approvePendingDeviceNow()}>
              Approve now with a known device
            </button>
            {request && (
              <button
                disabled={busy}
                className="secondary"
                onClick={() => returnToRequestingApp(pendingDevice.account, pendingDevice.device)}
              >
                Continue to requesting app anyway
              </button>
            )}
          </div>
          <small>
            Checks this browser's approval cache and its saved passkey for the requested account.
            If neither is authorized, open Demo A on a device that's already authorized, or wait
            for the delay.
          </small>
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

      <hr className="divider" />

      <section>
        <strong>Manage devices with Google</strong>
        <p>
          Resolve any account with Google and review its authorized devices by cleartext RP ID.
          Revoking a device, approving one, or rejecting one still queued behind the security delay
          all require an already-authorized device in this browser (checked automatically).
        </p>
        <div className="actions">
          <button disabled={dashboardBusy} onClick={() => void lookupAccount()}>
            Look up account
          </button>
        </div>
        <div ref={dashboardButton} className={`google-button${dashboardBusy ? " visible" : ""}`} />
        {dashboardStatus && (
          <div className="status-banner" data-tone={statusTone(dashboardStatus, dashboardBusy)}>
            <span className="status-icon" />
            <div className="status-banner-body">
              <span>{dashboardStatus}</span>
            </div>
          </div>
        )}
        {dashboardAccount && <span>Account: {dashboardAccount}</span>}
        {dashboardAccount && dashboardDevices.length > 0 && (
          <>
            <ul className="device-list">
              {dashboardDevices.map((authorizedDevice) => (
                <li key={authorizedDevice.address}>
                  <span>{authorizedDevice.rpId}</span>
                  <small>{authorizedDevice.address}</small>
                  {device && (
                    <button
                      disabled={dashboardBusy || !bundlerUrl}
                      className="danger"
                      onClick={() => void revokeDashboardDevice(authorizedDevice.address)}
                    >
                      {revokingDevice === authorizedDevice.address ? "Revoking…" : "Revoke"}
                    </button>
                  )}
                </li>
              ))}
            </ul>
            {device && (
              <div className="actions compact">
                <button
                  disabled={dashboardBusy || !bundlerUrl}
                  className="danger"
                  onClick={() => void revokeAllDashboardDevices()}
                >
                  Revoke all devices
                </button>
              </div>
            )}
          </>
        )}
        {dashboardAccount && dashboardPendingDevices.length > 0 && (
          <>
            <strong>Pending devices</strong>
            <ul className="device-list">
              {dashboardPendingDevices.map((pending) => (
                <li key={pending.address}>
                  <span>{pending.rpId}</span>
                  <small>{pending.address}</small>
                  <small>Ready at {new Date(pending.readyAt * 1000).toLocaleString()}</small>
                  <div className="actions compact">
                    <button
                      disabled={dashboardBusy}
                      onClick={() => void resolvePendingDashboardDevice(pending.address, "approve")}
                    >
                      {resolvingPendingDevice === pending.address ? "Working…" : "Approve"}
                    </button>
                    <button
                      disabled={dashboardBusy}
                      className="danger"
                      onClick={() => void resolvePendingDashboardDevice(pending.address, "reject")}
                    >
                      {resolvingPendingDevice === pending.address ? "Working…" : "Reject"}
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <footer className="legal-links">
        <a href="/privacy.html">Privacy policy</a>
      </footer>
      </main>
    </>
  );
}

function statusTone(message: string, busy: boolean): "busy" | "success" | "error" | "warning" | "idle" {
  if (busy) return "busy";
  const lower = message.toLowerCase();
  if (/(fail|error|reject|not found|no stored)/.test(lower)) return "error";
  if (/(configure|required|need)/.test(lower)) return "warning";
  if (/(authorized|ready|complete|found|revoked)/.test(lower)) return "success";
  return "idle";
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
