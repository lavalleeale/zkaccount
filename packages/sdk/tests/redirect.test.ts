import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import type { Hex } from "viem";
import {
  createPasskeyAuthorizationUrl,
  createPasskeyResultUrl,
  parsePasskeyAuthorizationRequest,
  parsePasskeyAuthorizationResult,
} from "../src/redirect";
import type { DeviceKey } from "../src/account";

Object.defineProperty(globalThis, "crypto", { value: webcrypto });

const SUPPORTED_CHAINS = [84_532, 11_155_111];
const keyPair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
  "sign",
  "verify",
]);
const jwk = await webcrypto.subtle.exportKey("jwk", keyPair.publicKey);
const fromBase64Url = (value: string): Hex => {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return `0x${Buffer.from(normalized, "base64").toString("hex")}`;
};
const publicKeyX = fromBase64Url(jwk.x!);
const publicKeyY = fromBase64Url(jwk.y!);
const publicKey = `0x04${publicKeyX.slice(2)}${publicKeyY.slice(2)}` as Hex;

const device: DeviceKey = {
  address: "0x1234567890123456789012345678901234567890",
  credentialId: "0x01020304",
  publicKeyX,
  publicKeyY,
  rpId: "wallet.example",
  rpIdHash: `0x${"33".repeat(32)}` as Hex,
};

function search(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

// Valid HTTPS callback round-trips and derives the public device metadata.
{
  const { url, state } = createPasskeyAuthorizationUrl({
    managerUrl: "https://manager.example/authorize",
    callback: "https://wallet.example/return?dapp=uniswap",
    chainId: 84_532,
    device,
  });
  assert.equal(url.origin, "https://manager.example");
  assert.equal(url.searchParams.get("rpId"), "wallet.example");
  assert.equal(url.searchParams.get("publicKey"), publicKey);
  assert.equal(url.searchParams.get("state"), state);

  const request = await parsePasskeyAuthorizationRequest(url.search, SUPPORTED_CHAINS);
  assert.equal(request.rpId, "wallet.example");
  assert.equal(request.publicKey, publicKey);
  assert.equal(request.chainId, 84_532);
  assert.equal(request.state, state);
  assert.equal(request.callback.toString(), "https://wallet.example/return?dapp=uniswap");
  assert.equal(request.device.rpId, "wallet.example");
  assert.equal(request.device.publicKeyX.toLowerCase(), publicKeyX);
  assert.equal(request.device.publicKeyY.toLowerCase(), publicKeyY);
}

// HTTP localhost and 127.0.0.1 callbacks are accepted for local development.
for (const host of ["localhost:5173", "127.0.0.1:5173"]) {
  const request = await parsePasskeyAuthorizationRequest(
    search({
      rpId: host.split(":")[0],
      publicKey,
      callback: `http://${host}/return`,
      state: "A".repeat(43),
      chainId: "84532",
    }),
    SUPPORTED_CHAINS,
  );
  assert.equal(request.callback.hostname, host.split(":")[0]);
}

// The callback hostname must exactly equal the requested RP ID.
await assert.rejects(
  parsePasskeyAuthorizationRequest(
    search({
      rpId: "wallet.example",
      publicKey,
      callback: "https://attacker.example/return",
      state: "A".repeat(43),
      chainId: "84532",
    }),
    SUPPORTED_CHAINS,
  ),
  /exactly match/,
);

// Unsupported chain IDs are rejected.
await assert.rejects(
  parsePasskeyAuthorizationRequest(
    search({
      rpId: "wallet.example",
      publicKey,
      callback: "https://wallet.example/return",
      state: "A".repeat(43),
      chainId: "999999",
    }),
    SUPPORTED_CHAINS,
  ),
  /not supported/,
);

// A malformed uncompressed P-256 key is rejected.
await assert.rejects(
  parsePasskeyAuthorizationRequest(
    search({
      rpId: "wallet.example",
      publicKey: "0x1234",
      callback: "https://wallet.example/return",
      state: "A".repeat(43),
      chainId: "84532",
    }),
    SUPPORTED_CHAINS,
  ),
  /uncompressed 65-byte/,
);

// A state that is not exactly 32 base64url-encoded bytes is rejected.
await assert.rejects(
  parsePasskeyAuthorizationRequest(
    search({
      rpId: "wallet.example",
      publicKey,
      callback: "https://wallet.example/return",
      state: "too-short",
      chainId: "84532",
    }),
    SUPPORTED_CHAINS,
  ),
  /32-byte base64url/,
);

// Callbacks must be absolute, HTTPS (or HTTP localhost), and carry no credentials or fragment.
for (const callback of [
  "not-a-url",
  "https://user:pass@wallet.example/return",
  "https://wallet.example/return#fragment",
  "http://wallet.example/return",
  "ftp://wallet.example/return",
]) {
  await assert.rejects(
    parsePasskeyAuthorizationRequest(
      search({
        rpId: "wallet.example",
        publicKey,
        callback,
        state: "A".repeat(43),
        chainId: "84532",
      }),
      SUPPORTED_CHAINS,
    ),
  );
}

// Missing required parameters are rejected with a descriptive error.
await assert.rejects(
  parsePasskeyAuthorizationRequest(search({ rpId: "wallet.example" }), SUPPORTED_CHAINS),
  /Missing publicKey/,
);

// The result URL preserves the callback's existing query parameters and appends namespaced fields.
{
  const callback = new URL("https://wallet.example/return?dapp=uniswap&ref=abc");
  const resultUrl = createPasskeyResultUrl(callback, {
    status: "approved",
    state: "B".repeat(43),
    chainId: 84_532,
    account: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    device: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  });
  assert.equal(resultUrl.searchParams.get("dapp"), "uniswap");
  assert.equal(resultUrl.searchParams.get("ref"), "abc");
  assert.equal(resultUrl.searchParams.get("zkaccount_status"), "approved");
  assert.equal(resultUrl.searchParams.get("zkaccount_state"), "B".repeat(43));
  assert.equal(resultUrl.searchParams.get("zkaccount_chain_id"), "84532");
  assert.equal(
    resultUrl.searchParams.get("zkaccount_account"),
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  );

  const parsed = parsePasskeyAuthorizationResult(resultUrl.search);
  assert.deepEqual(parsed, {
    status: "approved",
    state: "B".repeat(43),
    chainId: 84_532,
    account: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    device: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    error: undefined,
  });
}

// Rejection and failure carry a stable status and an optional error code, with no account/device.
{
  const rejected = createPasskeyResultUrl("https://wallet.example/return", {
    status: "rejected",
    state: "C".repeat(43),
    chainId: 84_532,
  });
  const parsedRejected = parsePasskeyAuthorizationResult(rejected.search);
  assert.equal(parsedRejected?.status, "rejected");
  assert.equal(parsedRejected?.account, undefined);

  const failed = createPasskeyResultUrl("https://wallet.example/return", {
    status: "failed",
    state: "D".repeat(43),
    chainId: 84_532,
    error: "chain_mismatch",
  });
  const parsedFailed = parsePasskeyAuthorizationResult(failed.search);
  assert.equal(parsedFailed?.status, "failed");
  assert.equal(parsedFailed?.error, "chain_mismatch");
}

// A URL with no recognized zkaccount_status parameter is not a result (e.g. the initial navigation).
assert.equal(parsePasskeyAuthorizationResult(""), undefined);
assert.equal(parsePasskeyAuthorizationResult("?zkaccount_status=bogus"), undefined);

// Each generated authorization request carries a fresh, non-repeating state.
{
  const first = createPasskeyAuthorizationUrl({
    managerUrl: "https://manager.example/authorize",
    callback: "https://wallet.example/return",
    chainId: 84_532,
    device,
  });
  const second = createPasskeyAuthorizationUrl({
    managerUrl: "https://manager.example/authorize",
    callback: "https://wallet.example/return",
    chainId: 84_532,
    device,
  });
  assert.notEqual(first.state, second.state);
  assert.match(first.state, /^[A-Za-z0-9_-]{43}$/);
}

console.log("redirect protocol tests passed");
