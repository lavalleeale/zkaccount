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
  type DeviceKey,
  type GoogleLoginResult,
  type GoogleProof,
} from "@zkaccount/sdk";
import "../../demo-a/src/style.css";

const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;
const factory = import.meta.env.VITE_ACCOUNT_FACTORY as Address | undefined;
const rpcUrl = import.meta.env.VITE_BASE_SEPOLIA_RPC_URL as string | undefined;
const bundlerUrl = import.meta.env.VITE_BUNDLER_URL as string | undefined;
const passkeyOptions = { scope: "demo-b", displayName: "zkAccount Demo B" };

function App() {
  const button = useRef<HTMLDivElement>(null);
  const wallet = useMemo(
    () =>
      factory ? new Google4337Client({ factory, bundlerUrl: bundlerUrl ?? "", rpcUrl }) : undefined,
    [],
  );
  const [status, setStatus] = useState("No wallet state shared with Demo A");
  const [login, setLogin] = useState<GoogleLoginResult>();
  const [proof, setProof] = useState<GoogleProof>();
  const [device, setDevice] = useState<DeviceKey>();
  const [account, setAccount] = useState<Address>();
  const [balance, setBalance] = useState(0n);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);

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
      setAccount(undefined);
      setBalance(0n);
      setAuthorized(false);
      setStatus(
        nextDevice.protection === "passkey-prf"
          ? "Passkey ready. Continue with Google to recover the smart account."
          : "Passkey ready with a memory-only device key. Continue with Google.",
      );
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
      nextAuthorized
        ? "Demo B device is authorized on the shared account"
        : "Demo B device needs Google authorization",
    );
  }

  async function start() {
    if (!button.current || !clientId || !factory || !wallet || !device) {
      setStatus(
        device
          ? "Set VITE_GOOGLE_CLIENT_ID and VITE_ACCOUNT_FACTORY first"
          : "Create or unlock the Demo B passkey first",
      );
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
        chainId: 84532,
        button: button.current,
        device,
      });
      setLogin(result);
      setDevice(result.device);
      setStatus("Checking whether the Demo B device is already authorized");
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
        setStatus("Demo B device is already authorized. No Google proof is needed.");
        return;
      }
      setStatus("Device authorization is required. Warming up the prover");
      await warmGoogleProver();
      setStatus("Generating proof in this independent origin");
      const generatedProof = await proveGoogleAuthorization(result);
      setProof(generatedProof);
      setStatus(
        bundlerUrl
          ? `Same identity resolved. Authorize Demo B's independent key on ${predicted}.`
          : `Account resolved. Configure VITE_BUNDLER_URL to submit the UserOperation.`,
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

  return (
    <main>
      <p className="eyebrow">Independent origin · Demo B</p>
      <h1>Recover the same account</h1>
      <p>This app uses an independent passkey device key for this origin.</p>
      <div className="actions">
        <button disabled={busy} onClick={() => void loadPasskey(false)}>
          Unlock passkey
        </button>
        <button disabled={busy} className="secondary" onClick={() => void loadPasskey(true)}>
          Create passkey
        </button>
        <button disabled={busy || !device} onClick={start}>
          Continue with Google
        </button>
        {proof && !authorized && (
          <button disabled={busy || !bundlerUrl} onClick={authorizeDevice}>
            Authorize Demo B device
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
            Revoke Demo B device
          </button>
        )}
      </div>
      <div ref={button} className="google-button" />
      <section>
        <strong>Status</strong>
        <span>{status}</span>
      </section>
      {account && (
        <section>
          <strong>Portable smart account</strong>
          <span>{account}</span>
          <span>Balance: {formatEther(balance)} Base Sepolia ETH</span>
          <span>Demo B passkey device: {device?.address ?? "Create or unlock a passkey"}</span>
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
          <strong>Local authentication result</strong>
          <span>Audience: {login.claims.aud}</span>
          <span>Nonce matched: yes</span>
        </section>
      )}
      {proof && (
        <section>
          <strong>Private proof</strong>
          <span>Identity commitment: {proof.publicInputs[0]}</span>
          <span>Proof size: {(proof.proof.length - 2) / 2} bytes</span>
          <span>Compare the smart-account address—not browser state—with Demo A.</span>
        </section>
      )}
      {!bundlerUrl && (
        <small>
          Set VITE_BUNDLER_URL to a Base Sepolia ERC-4337 bundler supporting EntryPoint v0.8.
        </small>
      )}
      <small>
        PRF-capable passkeys deterministically derive the device key in memory. If PRF is
        unavailable, a random device key exists only for this page session and is never stored.
      </small>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
