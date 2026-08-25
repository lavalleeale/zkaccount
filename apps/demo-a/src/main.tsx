import React, { useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { formatEther, type Address } from "viem";
import {
  Google4337Client,
  createPasskeyDeviceKey,
  googleIdentityCommitment,
  loginWithGoogle,
  proveGoogleAuthorization,
  unlockPasskeyDeviceKey,
  warmGoogleProver,
  type AuthorizedClientId,
  type DeviceKey,
  type GoogleLoginResult,
  type GoogleProof,
} from "@zkaccount/sdk";
import "./style.css";

const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;
const factory = import.meta.env.VITE_ACCOUNT_FACTORY as Address | undefined;
const rpcUrl = import.meta.env.VITE_BASE_SEPOLIA_RPC_URL as string | undefined;
const bundlerUrl = import.meta.env.VITE_BUNDLER_URL as string | undefined;
const passkeyOptions = { scope: "demo-a", displayName: "zkAccount Demo A" };

function App() {
  const button = useRef<HTMLDivElement>(null);
  const wallet = useMemo(
    () =>
      factory ? new Google4337Client({ factory, bundlerUrl: bundlerUrl ?? "", rpcUrl }) : undefined,
    [],
  );
  const [status, setStatus] = useState("Ready");
  const [login, setLogin] = useState<GoogleLoginResult>();
  const [proof, setProof] = useState<GoogleProof>();
  const [device, setDevice] = useState<DeviceKey>();
  const [account, setAccount] = useState<Address>();
  const [balance, setBalance] = useState(0n);
  const [authorized, setAuthorized] = useState(false);
  const [audienceClientId, setAudienceClientId] = useState(clientId ?? "");
  const [authorizedClientIds, setAuthorizedClientIds] = useState<AuthorizedClientId[]>([]);
  const [busy, setBusy] = useState(false);

  async function loadPasskey(create: boolean) {
    setBusy(true);
    setStatus(create ? "Creating Demo A passkey" : "Unlocking Demo A passkey");
    try {
      const nextDevice = create
        ? await createPasskeyDeviceKey(passkeyOptions)
        : await unlockPasskeyDeviceKey(passkeyOptions);
      setDevice(nextDevice);
      setLogin(undefined);
      setProof(undefined);
      setAccount(undefined);
      setBalance(0n);
      setAuthorized(false);
      setAuthorizedClientIds([]);
      setStatus(
        nextDevice.protection === "passkey-prf"
          ? "Passkey ready. Choose Continue with Google to resolve the smart account."
          : "Memory-only device key ready. Choose Continue with Google.",
      );
      await start(nextDevice);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function refresh(address = account, localDevice = device) {
    if (!wallet || !address || !localDevice) return;
    const [nextBalance, nextAuthorized, nextClientIds] = await Promise.all([
      wallet.getBalance(address),
      wallet.isDeviceAuthorized(address, localDevice.address),
      wallet.listAuthorizedClientIds(address),
    ]);
    setBalance(nextBalance);
    setAuthorized(nextAuthorized);
    setAuthorizedClientIds(nextClientIds);
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
    setAuthorizedClientIds([]);
    setStatus("Authenticating with Google");
    try {
      const result = await loginWithGoogle({
        clientId,
        factory,
        chainId: 84532,
        button: button.current,
        device: localDevice,
      });
      setLogin(result);
      setDevice(result.device);
      setStatus("Checking whether this device is already authorized");
      const identity = await googleIdentityCommitment(result.claims);
      const predicted = await wallet.getAccountAddress(identity);
      const [nextBalance, nextAuthorized, nextClientIds] = await Promise.all([
        wallet.getBalance(predicted),
        wallet.isDeviceAuthorized(predicted, result.device.address),
        wallet.listAuthorizedClientIds(predicted),
      ]);
      setAccount(predicted);
      setBalance(nextBalance);
      setAuthorized(nextAuthorized);
      setAuthorizedClientIds(nextClientIds);
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
      setStatus(error instanceof Error ? error.message : String(error));
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

  async function setAudience(enabled: boolean, clientIdToUpdate = audienceClientId.trim()) {
    if (!wallet || !account || !device || !bundlerUrl || !clientIdToUpdate) return;
    setBusy(true);
    try {
      if (enabled) {
        await wallet.addAudience(account, device, clientIdToUpdate, setStatus);
      } else {
        await wallet.removeAudience(account, device, clientIdToUpdate, setStatus);
      }
      setAuthorizedClientIds(await wallet.listAuthorizedClientIds(account));
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <p className="eyebrow">Independent origin · Demo A</p>
      <h1>Google → ERC-4337</h1>
      <p>
        Authenticate, prove the Google credential locally, then authorize this origin's device key.
      </p>
      <div className="actions">
        <button disabled={busy} onClick={() => void loadPasskey(false)}>
          Unlock passkey
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
      {account && (
        <section>
          <strong>Smart account</strong>
          <span>{account}</span>
          <span>Balance: {formatEther(balance)} Base Sepolia ETH</span>
          <span>Passkey device: {device?.address ?? "Create or unlock a passkey"}</span>
          {device && (
            <span>
              Key protection:{" "}
              {device.protection === "passkey-prf"
                ? "passkey PRF"
                : "memory only (not recoverable after reload)"}
            </span>
          )}
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
      {account && (
        <section>
          <strong>Approved Google client IDs</strong>
          {authorizedClientIds.length === 0 ? (
            <span>No approved client IDs found</span>
          ) : (
            <ul className="client-ids">
              {authorizedClientIds.map(({ audienceHash, clientId: authorizedClientId }) => (
                <li key={audienceHash}>
                  <span>{authorizedClientId}</span>
                  <button
                    type="button"
                    className="remove-client-id"
                    disabled={busy || !authorized || !bundlerUrl}
                    aria-label={`Remove ${authorizedClientId}`}
                    title="Remove client ID"
                    onClick={() => void setAudience(false, authorizedClientId)}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          )}
          <label htmlFor="audience-client-id">OAuth client ID</label>
          <input
            id="audience-client-id"
            value={audienceClientId}
            onChange={(event) => setAudienceClientId(event.target.value)}
            placeholder="client-id.apps.googleusercontent.com"
            spellCheck={false}
          />
          <div className="actions">
            <button disabled={busy} className="secondary" onClick={() => void refresh()}>
              Refresh list
            </button>
            <button
              disabled={busy || !authorized || !bundlerUrl || !audienceClientId.trim()}
              onClick={() => void setAudience(true)}
            >
              Approve client ID
            </button>
          </div>
          <small>
            Removing the root client ID disables future Google recovery through that client.
            Device-key transactions continue to work.
          </small>
        </section>
      )}
      {!bundlerUrl && (
        <small>
          Set VITE_BUNDLER_URL to a Base Sepolia ERC-4337 bundler supporting EntryPoint v0.8.
          Account prediction and proof generation work without it.
        </small>
      )}
      <small>
        PRF-capable passkeys deterministically derive the device key in memory. If PRF is
        unavailable, a random device key exists only for this page session and is never stored.
      </small>
      <footer className="legal-links">
        <a href="/privacy.html">Privacy policy</a>
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
