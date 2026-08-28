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
import {
  AddressDisplay,
  AppShell,
  Card,
  EmptyState,
  KeyValue,
  PageIntro,
  StatusPanel,
  Steps,
  TechnicalDetails,
  type StatusTone,
} from "@zkaccount/ui";
import "@zkaccount/ui/styles.css";
import {
  authorizationCompletionCopy,
  authorizationStep,
  resolveAuthorizationPhase,
  type AuthorizationOutcome,
} from "./authorization-state";
import { resolveDemoARoute, type DemoARoute } from "./routing";
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
  const [authorizationOutcome, setAuthorizationOutcome] = useState<AuthorizationOutcome>();
  const [pendingDevice, setPendingDevice] = useState<PendingDeviceState>();
  const [dashboardStatus, setDashboardStatus] = useState("");
  const [dashboardBusy, setDashboardBusy] = useState(false);
  const [dashboardAccount, setDashboardAccount] = useState<Address>();
  const [dashboardDevices, setDashboardDevices] = useState<AuthorizedDevice[]>([]);
  const [revokingDevice, setRevokingDevice] = useState<Address>();
  const [dashboardPendingDevices, setDashboardPendingDevices] = useState<PendingDeviceInfo[]>([]);
  const [resolvingPendingDevice, setResolvingPendingDevice] = useState<Address>();
  const [signingIn, setSigningIn] = useState(false);
  const [requestChecked, setRequestChecked] = useState(false);
  const [route, setRoute] = useState<DemoARoute>(() =>
    resolveDemoARoute(window.location.pathname, window.location.search),
  );

  useEffect(() => {
    void parsePasskeyAuthorizationRequest(
      window.location.search,
      Object.values(networks).map((item) => item.chain.id),
    )
      .then(setRequest)
      .catch((error: unknown) => {
        if (window.location.search)
          setStatus(error instanceof Error ? error.message : String(error));
      })
      .finally(() => setRequestChecked(true));
  }, []);

  useEffect(() => {
    const onPopState = () =>
      setRoute(resolveDemoARoute(window.location.pathname, window.location.search));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!busy && !dashboardBusy) return;
      event.preventDefault();
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [busy, dashboardBusy]);

  function navigate(next: string) {
    if (
      (busy || dashboardBusy) &&
      !window.confirm("An operation is still running. Leave this screen?")
    )
      return;
    const target = resolveDemoARoute(next, "");
    window.history.pushState(null, "", target);
    setRoute(target);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function approveRequest() {
    if (!request) return;
    const requestedDevice = { ...request.device, credentialId: "0x" as `0x${string}` };
    setDevice(requestedDevice);
    await start(requestedDevice);
  }

  function rejectRequest() {
    if (!request) return;
    setAuthorizationOutcome("rejected");
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
          setStatus(
            "Local device is authorized (used the cached Google identity, no sign-in needed).",
          );
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
        setAuthorizationOutcome("failed");
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
        setAuthorizationOutcome("failed");
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
    setAuthorizationOutcome("approved");
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
      await wallet.approveDevice(pendingDevice.account, approver, pendingDevice.device, setStatus);
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

  const authorizationPhase = resolveAuthorizationPhase({
    hasDevice: device !== undefined,
    hasLogin: login !== undefined,
    hasProof: proof !== undefined,
    authorized,
    pending: pendingDevice !== undefined,
    complete: returnUrl !== undefined,
    signingIn,
  });
  const authorizationCopy = authorizationOutcome
    ? authorizationCompletionCopy(authorizationOutcome)
    : undefined;
  const networkControl = (
    <div className="network-control">
      <label htmlFor={`network-${route.slice(1) || "home"}`}>Network</label>
      <select
        id={`network-${route.slice(1) || "home"}`}
        value={selectedNetworkKey}
        disabled={requestedNetworkKey !== undefined || busy || dashboardBusy}
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

  return (
    <AppShell
      product="zkAccount"
      context="Passkey manager"
      network={network.chain.name}
      currentPath={route}
      onNavigate={navigate}
      nav={[
        { href: "/", label: "Home" },
        { href: "/devices", label: "Devices" },
        { href: "/lab", label: "Lab" },
      ]}
    >
      {route === "/" && (
        <div className="manager-home stack">
          <Card className="hero-card">
            <span className="eyebrow">Private identity · portable account</span>
            <h1>Your account, wherever you go.</h1>
            <p className="muted">
              Authorize origin-bound passkeys with Google without revealing your identity onchain.
              Once connected, every action is approved by your authenticator—not a backend.
            </p>
            <div className="actions">
              <button className="primary-button blue" onClick={() => navigate("/devices")}>
                Manage my devices
              </button>
              <button className="secondary-button" onClick={() => navigate("/lab")}>
                Open developer lab
              </button>
            </div>
          </Card>
          <div className="grid three">
            <Card className="feature-card" eyebrow="01" title="Private by design">
              <p>Your Google subject stays inside a local zero-knowledge proof.</p>
              <span className="pill">Browser proved</span>
            </Card>
            <Card className="feature-card" eyebrow="02" title="Portable across apps">
              <p>Independent origins resolve the same deterministic ERC-4337 account.</p>
              <span className="pill">No seed export</span>
            </Card>
            <Card className="feature-card" eyebrow="03" title="Passkey secured">
              <p>Every transaction requires a fresh user-verified WebAuthn assertion.</p>
              <span className="pill">Self custody</span>
            </Card>
          </div>
        </div>
      )}

      {route === "/authorize" && (
        <div className="journey">
          <PageIntro
            eyebrow="Secure handoff"
            title="Authorize this app."
            description="Review the independent origin, prove your Google identity privately, and add its passkey to your smart account."
          />
          {!requestChecked && (
            <StatusPanel tone="busy">Validating the incoming authorization request…</StatusPanel>
          )}
          {requestChecked && !request && (
            <Card className="hero-card">
              <EmptyState
                title="No authorization request found"
                action={
                  <button className="secondary-button" onClick={() => navigate("/")}>
                    Return home
                  </button>
                }
              >
                {status === "Ready"
                  ? "Start from an app that uses zkAccount. Its signed handoff details will appear here for review."
                  : status}
              </EmptyState>
            </Card>
          )}
          {request && (
            <Card className="hero-card">
              <Steps
                steps={["Review", "Google", "Prove", "Authorize", "Done"]}
                active={authorizationStep(authorizationPhase)}
              />
              {returnUrl && authorizationOutcome && authorizationCopy ? (
                <div className="centered">
                  <div className="completion-mark" data-outcome={authorizationOutcome}>
                    {authorizationCopy.mark}
                  </div>
                  <h2>{authorizationCopy.title}</h2>
                  <p className="muted">{authorizationCopy.description}</p>
                  <div className="actions">
                    <a className="button-link primary-button blue" href={returnUrl}>
                      Return to {request.callback.host}
                    </a>
                  </div>
                </div>
              ) : pendingDevice ? (
                <div>
                  <span className="eyebrow">Security delay</span>
                  <h2 style={{ marginTop: 10 }}>This device is queued</h2>
                  <p className="muted">
                    It becomes active at {new Date(pendingDevice.readyAt * 1000).toLocaleString()},
                    or an existing device can approve it now.
                  </p>
                  <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
                  <div className="actions">
                    <button
                      className="primary-button"
                      disabled={busy || !bundlerUrl}
                      onClick={() => void approvePendingDeviceNow()}
                    >
                      Approve with a known device
                    </button>
                    <button
                      className="secondary-button"
                      disabled={busy}
                      onClick={() =>
                        returnToRequestingApp(pendingDevice.account, pendingDevice.device)
                      }
                    >
                      Return while pending
                    </button>
                  </div>
                </div>
              ) : (
                <div className="stack">
                  <div className="request-summary">
                    <KeyValue label="Requesting app" value={request.callback.host} />
                    <KeyValue label="Passkey domain" value={request.rpId} />
                    <KeyValue label="Network" value={network.chain.name} />
                    <KeyValue label="Action" value="Add a passkey" />
                  </div>
                  <div className="privacy-callout">
                    <b>Private proof</b>
                    <span>
                      The Google ID token and subject never leave this browser and are not written
                      onchain.
                    </span>
                  </div>
                  {busy && authorizationPhase === "prove" && (
                    <div className="proof-visual">
                      <span>LOCAL ZK</span>
                    </div>
                  )}
                  <div ref={button} className={`google-button${signingIn ? " visible" : ""}`} />
                  <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
                  {account && (
                    <AddressDisplay label="Deterministic smart account" value={account} />
                  )}
                  {account && (
                    <div className="account-strip">
                      <KeyValue label="Balance" value={`${formatEther(balance)} ETH`} />
                      <KeyValue label="Device" value={authorized ? "Active" : "Not active"} />
                      <KeyValue label="Network" value={network.chain.name} />
                    </div>
                  )}
                  <div className="actions">
                    {!device && (
                      <button
                        className="primary-button blue"
                        disabled={busy}
                        onClick={() => void approveRequest()}
                      >
                        Continue with Google
                      </button>
                    )}
                    {device && !proof && !authorized && !busy && (
                      <button className="primary-button blue" onClick={() => void start(device)}>
                        Try Google again
                      </button>
                    )}
                    {proof && !authorized && (
                      <button
                        className="primary-button blue"
                        disabled={busy || !bundlerUrl}
                        onClick={() => void authorizeDevice()}
                      >
                        Authorize on {network.chain.name}
                      </button>
                    )}
                    {authorized && (
                      <button
                        className="primary-button blue"
                        disabled={busy || !account || !device}
                        onClick={() =>
                          account && device && returnToRequestingApp(account, device.address)
                        }
                      >
                        Complete request
                      </button>
                    )}
                    <button className="danger-button" disabled={busy} onClick={rejectRequest}>
                      Reject request
                    </button>
                    {account && (
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => void refresh()}
                      >
                        Refresh balance
                      </button>
                    )}
                  </div>
                  {proof && (
                    <TechnicalDetails summary="View private-proof details">
                      <KeyValue label="Identity commitment" value={proof.publicInputs[0]} mono />
                      <KeyValue
                        label="Proof size"
                        value={`${(proof.proof.length - 2) / 2} bytes`}
                      />
                      <KeyValue
                        label="Authorization expires"
                        value={new Date(
                          Number(BigInt(proof.publicInputs[5])) * 1000,
                        ).toLocaleString()}
                      />
                      <KeyValue label="Passkey device" value={device?.address ?? "—"} mono />
                    </TechnicalDetails>
                  )}
                  {!bundlerUrl && (
                    <StatusPanel tone="warning">
                      Configure an EntryPoint v0.8 bundler URL to submit authorization. Prediction
                      and proof generation still work.
                    </StatusPanel>
                  )}
                </div>
              )}
            </Card>
          )}
        </div>
      )}

      {route === "/devices" && (
        <div className="device-page">
          <PageIntro
            eyebrow="Account security"
            title="Your trusted devices."
            description="Resolve your account privately with Google, then review active and time-delayed passkeys by their domain."
            aside={networkControl}
          />
          <div className="split">
            <Card title="Device access" eyebrow="Google account">
              <p className="muted">
                Google is used only to locate the deterministic account. Approving or removing a
                device still requires an authorized passkey in this browser.
              </p>
              <div className="actions">
                <button
                  className="primary-button blue"
                  disabled={dashboardBusy}
                  onClick={() => void lookupAccount()}
                >
                  Continue with Google
                </button>
              </div>
              <div
                ref={dashboardButton}
                className={`google-button${dashboardBusy ? " visible" : ""}`}
              />
              {dashboardStatus && (
                <StatusPanel tone={statusTone(dashboardStatus, dashboardBusy)}>
                  {dashboardStatus}
                </StatusPanel>
              )}
              {dashboardAccount && (
                <div style={{ marginTop: 16 }}>
                  <AddressDisplay label="Smart account" value={dashboardAccount} />
                </div>
              )}
            </Card>
            <Card title="Security model" eyebrow="What stays private">
              <p className="muted">
                The account address and public credential metadata are visible. Your Google subject,
                token, proof, and authenticator key remain private.
              </p>
              <span className="pill">User verified</span>
            </Card>
          </div>
          {dashboardAccount && (
            <div className="grid" style={{ marginTop: 18 }}>
              <Card title={`Active devices · ${dashboardDevices.length}`} eyebrow="Authorized">
                {dashboardDevices.length === 0 ? (
                  <p className="muted">No active devices were found.</p>
                ) : (
                  <ul className="device-list">
                    {dashboardDevices.map((item) => (
                      <li className="device-row" key={item.address}>
                        <div>
                          <b>{item.rpId}</b>
                          <code>{item.address}</code>
                        </div>
                        <button
                          className="danger-button"
                          disabled={dashboardBusy || !bundlerUrl}
                          onClick={() => void revokeDashboardDevice(item.address)}
                        >
                          {revokingDevice === item.address ? "Revoking…" : "Revoke"}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                {dashboardDevices.length > 0 && (
                  <div className="actions">
                    <button
                      className="danger-button"
                      disabled={dashboardBusy || !bundlerUrl}
                      onClick={() => void revokeAllDashboardDevices()}
                    >
                      Revoke all devices
                    </button>
                  </div>
                )}
              </Card>
              <Card
                title={`Pending devices · ${dashboardPendingDevices.length}`}
                eyebrow="Security delay"
              >
                {dashboardPendingDevices.length === 0 ? (
                  <p className="muted">No devices are waiting for approval.</p>
                ) : (
                  <ul className="device-list">
                    {dashboardPendingDevices.map((pending) => (
                      <li className="device-row" key={pending.address}>
                        <div>
                          <b>{pending.rpId}</b>
                          <code>{pending.address}</code>
                          <small>Ready {new Date(pending.readyAt * 1000).toLocaleString()}</small>
                        </div>
                        <div className="actions">
                          <button
                            className="secondary-button"
                            disabled={dashboardBusy}
                            onClick={() =>
                              void resolvePendingDashboardDevice(pending.address, "approve")
                            }
                          >
                            {resolvingPendingDevice === pending.address ? "Working…" : "Approve"}
                          </button>
                          <button
                            className="danger-button"
                            disabled={dashboardBusy}
                            onClick={() =>
                              void resolvePendingDashboardDevice(pending.address, "reject")
                            }
                          >
                            Reject
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>
          )}
        </div>
      )}

      {route === "/lab" && (
        <div>
          <PageIntro
            eyebrow="Developer tools"
            title="Protocol lab."
            description="Exercise the standalone passkey and ERC-4337 paths while keeping implementation detail out of the primary authorization journey."
            aside={networkControl}
          />
          <div className="split">
            <Card title="Local device" eyebrow="Standalone flow">
              <p className="muted">
                Create or load this origin’s passkey, then resolve and authorize the account with
                Google.
              </p>
              <div className="actions">
                <button
                  className="primary-button"
                  disabled={busy}
                  onClick={() => void loadPasskey(false)}
                >
                  Load stored passkey
                </button>
                <button
                  className="secondary-button"
                  disabled={busy}
                  onClick={() => void loadPasskey(true)}
                >
                  Create passkey
                </button>
              </div>
              <div ref={button} className={`google-button${signingIn ? " visible" : ""}`} />
              <div style={{ marginTop: 18 }}>
                <StatusPanel tone={statusTone(status, busy)}>{status}</StatusPanel>
              </div>
            </Card>
            <Card title="Onchain actions" eyebrow="ERC-4337">
              <div className="actions">
                {proof && !authorized && (
                  <button
                    className="primary-button blue"
                    disabled={busy || !bundlerUrl}
                    onClick={() => void authorizeDevice()}
                  >
                    Deploy / authorize
                  </button>
                )}
                {account && (
                  <button
                    className="secondary-button"
                    disabled={busy}
                    onClick={() => void refresh()}
                  >
                    Refresh
                  </button>
                )}
                {authorized && (
                  <button
                    className="primary-button"
                    disabled={busy || !bundlerUrl}
                    onClick={() => void sendSelfTransaction()}
                  >
                    Send 0 ETH to self
                  </button>
                )}
                {authorized && (
                  <button
                    className="danger-button"
                    disabled={busy || !bundlerUrl}
                    onClick={() => void revokeLocalDevice()}
                  >
                    Revoke this device
                  </button>
                )}
                {authorized && (
                  <button
                    className="danger-button"
                    disabled={busy || !bundlerUrl}
                    onClick={() => void revokeAllLocalDevices()}
                  >
                    Revoke all devices
                  </button>
                )}
              </div>
              {!bundlerUrl && (
                <StatusPanel tone="warning">
                  Configure an EntryPoint v0.8 bundler URL to submit authorization or onchain
                  actions.
                </StatusPanel>
              )}
            </Card>
          </div>
          {(account || device || proof) && (
            <Card title="Development claims" eyebrow="Current runtime" className="">
              <div className="grid three">
                <KeyValue label="Account" value={account ?? "Not resolved"} mono />
                <KeyValue label="Balance" value={`${formatEther(balance)} ETH`} />
                <KeyValue label="Authorized" value={authorized ? "Yes" : "No"} />
                <KeyValue label="Passkey device" value={device?.address ?? "Not loaded"} mono />
                <KeyValue label="Protection" value={device ? "Native WebAuthn P-256" : "—"} />
                <KeyValue
                  label="Google subject input"
                  value={login?.claims.sub ?? "Available after Google login"}
                  mono
                />
              </div>
              {proof && (
                <TechnicalDetails summary="Proof and public inputs">
                  <KeyValue label="Identity commitment" value={proof.publicInputs[0]} mono />
                  <KeyValue label="Proof size" value={`${(proof.proof.length - 2) / 2} bytes`} />
                  <KeyValue
                    label="Authorization expires"
                    value={new Date(Number(BigInt(proof.publicInputs[5])) * 1000).toLocaleString()}
                  />
                </TechnicalDetails>
              )}
            </Card>
          )}
        </div>
      )}
    </AppShell>
  );
}

function statusTone(message: string, busy: boolean): StatusTone {
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
