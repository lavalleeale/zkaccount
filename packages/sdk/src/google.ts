import {
  bytesToHex,
  concat,
  hexToBytes,
  numberToHex,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import type { DeviceKey } from "./account";

const LOGIN_DOMAIN = "GOOGLE_4337_LOGIN_V1";

export interface LoginChallenge {
  deviceAddress: Address;
  loginRandomness: Hex;
  proofExpiry: number;
  chainId: number;
  factory: Address;
  nonce: Hex;
}

export interface GoogleClaims {
  iss: string;
  aud: string;
  sub: string;
  nonce?: string;
  iat: number;
  exp: number;
}

export interface GoogleLoginResult {
  idToken: string;
  claims: GoogleClaims;
  challenge: LoginChallenge;
  device: DeviceKey;
}

export interface GoogleLoginOptions {
  clientId: string;
  chainId: number;
  factory: Address;
  button: HTMLElement;
  device: DeviceKey;
}

declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize(config: {
            client_id: string;
            nonce: string;
            callback: (response: { credential: string }) => void;
          }): void;
          renderButton(parent: HTMLElement, options: Record<string, unknown>): void;
          prompt(): void;
        };
      };
    };
  }
}

export async function createLoginChallenge(
  chainId: number,
  factory: Address,
  deviceAddress: Address,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<LoginChallenge> {
  const randomness = crypto.getRandomValues(new Uint8Array(32));
  const proofExpiry = nowSeconds + 10 * 60;
  // Exact preimage: UTF-8 domain || uint256(chainId) || address(factory) ||
  // address(device) || uint64(expiry) || bytes32(randomness).
  const preimage = concat([
    bytesToHex(stringToBytes(LOGIN_DOMAIN)),
    numberToHex(chainId, { size: 32 }),
    factory,
    deviceAddress,
    numberToHex(proofExpiry, { size: 8 }),
    bytesToHex(randomness),
  ]);
  const digestInput = new Uint8Array(hexToBytes(preimage));
  const digest = await crypto.subtle.digest("SHA-256", digestInput);
  return {
    deviceAddress,
    loginRandomness: bytesToHex(randomness),
    proofExpiry,
    chainId,
    factory,
    nonce: bytesToHex(new Uint8Array(digest)),
  };
}

export async function loginWithGoogle(options: GoogleLoginOptions): Promise<GoogleLoginResult> {
  const challenge = await createLoginChallenge(
    options.chainId,
    options.factory,
    options.device.address,
  );

  const google = await waitForGoogleIdentityServices();
  return new Promise((resolve, reject) => {
    google.accounts.id.initialize({
      client_id: options.clientId,
      nonce: challenge.nonce,
      callback: ({ credential }) => {
        try {
          const claims = parseGoogleIdToken(credential);
          if (claims.nonce !== challenge.nonce) {
            throw new Error("Google ID token nonce does not match the local login challenge");
          }
          if (claims.aud !== options.clientId) {
            throw new Error("Google ID token audience does not match this OAuth client");
          }
          resolve({ idToken: credential, claims, challenge, device: options.device });
        } catch (error) {
          reject(error);
        }
      },
    });
    options.button.replaceChildren();
    google.accounts.id.renderButton(options.button, {
      type: "standard",
      theme: "outline",
      size: "large",
      text: "continue_with",
    });
  });
}

export function parseGoogleIdToken(idToken: string): GoogleClaims {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Malformed Google ID token");
  const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return JSON.parse(atob(padded)) as GoogleClaims;
}

async function waitForGoogleIdentityServices(timeoutMs = 10_000): Promise<NonNullable<Window["google"]>> {
  const started = Date.now();
  while (!window.google?.accounts?.id) {
    if (Date.now() - started > timeoutMs) {
      throw new Error("Google Identity Services script did not load");
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return window.google;
}
