# Google ZK ERC-4337 portability MVP

This repository is an incremental implementation of a wallet whose deterministic
smart-account identity comes from a privately proven Google OIDC subject. The
real Noir JWT/RS256 proof, generated UltraHonk verifier, threaded browser
prover, Base Sepolia deployment, and provider-neutral EntryPoint v0.8 bundler
client are implemented. A live bundler endpoint and the final portability
transaction run remain environment-dependent.

## Implemented

- deterministic CREATE2 account address derived from the hidden identity
  commitment (plus fixed factory configuration);
- an undeployed/deployed address match and idempotent factory deployment;
- EntryPoint-only `validateUserOp` and `execute`;
- mode `0x00` secp256k1 device signatures with low-s enforcement;
- mode `0x01` Google-proof validation, bound to one exact `addDevice` call;
- account-local audience enable/disable policy and a Google JWK hash registry
  updated by an authenticated Chainlink CRE report;
- no mutable authorization during validation: bootstrap execution performs the
  self-call only after validation;
- two independent Vite apps using GIS, passkey-derived device keys, and a
  nonce-bound ten-minute login challenge;
- constrained base64url reconstruction of the signed JWT header and payload;
- RS256 verification, issuer/algorithm/audience/subject/nonce/expiry bindings,
  private Poseidon2 subject identity, and JWK modulus commitment;
- an optimized generated Solidity verifier validated against a real circuit
  proof and an in-browser bb.js WASM proving path;
- a local JWK diagnostic that emits the circuit key hash;
- a scheduled Chainlink CRE workflow that fetches Google's JWKS with identical
  DON consensus and atomically rotates the onchain key set through the Keystone
  forwarder;
- Base Sepolia v0.8 UserOperation construction, gas estimation, submission,
  receipt polling, Google bootstrap encoding, and raw-hash device signatures;
- counterfactual funding/authorization UI, passkey unlock flows, and
  device-signed zero-value transactions in both demos.

Account creation itself installs no device. Anyone may deploy a counterfactual
account, but deployment grants no authority, so racing `createAccount(identity)`
cannot install an attacker's key.

## Local checks

```sh
nix-shell -p foundry --run 'forge test -vv'
npm install
npm run circuit:fixture
npm run circuit:test-negative
npm run circuit:test-bbjs
npm run circuit:generate-verifier
npm run typecheck
npm run typecheck:cre
npm run build
```

## Google JWKS updates through Chainlink CRE

The registry has no manual `setKey` path. `cre/google-jwks/main.ts` runs on a
six-hour cron schedule, fetches Google's published signing keys independently
on CRE nodes, normalizes and sorts their circuit commitments, and requires
identical consensus before writing the complete set onchain. A successful
report adds the current keys and revokes keys absent from the new set in one
transaction.

Deploy `GoogleKeyRegistry` with the account owner, the CRE Keystone forwarder
for the target chain, and the address that owns the deployed CRE workflow. The
receiver accepts only forwarder calls whose metadata identifies that owner and
the `googlejwks` workflow name. Then set the deployed registry address in
`cre/google-jwks/config.staging.json` and use the CRE CLI from that directory:

```sh
bun install
cre workflow simulate --target staging-settings --config config.staging.json main.ts
cre workflow deploy --target staging-settings
```

The zero registry address in the checked-in staging config is intentionally a
deployment placeholder. The registry starts empty, so bootstrap proofs are not
accepted until its first successful CRE report. A Google key rotation can also
temporarily precede the next scheduled report; shorten the schedule if that
availability window is unacceptable.

Circuit generation is pinned to Nargo `1.0.0-beta.26`, `noir_rsa` `v0.11.0`,
and bb.js `5.2.0`. `circuit:generate-verifier` accepts `NARGO_BIN`, `BB_BIN`,
and optional `ZK_BIN_WRAPPER` environment variables for NixOS/CI tool paths.
The current circuit expands to 262,021 Barretenberg gates, just below the
2^18 proving-domain boundary. Set `BBJS_THREADS` when running
`circuit:test-bbjs` to benchmark a particular worker count.

For GIS, copy each app's `.env.example`, configure an OAuth web client for the
actual origin, and set `VITE_BUNDLER_URL` to a Base Sepolia bundler supporting
EntryPoint v0.8. Then run `npm run dev:a` or `npm run dev:b`. The browser receives
the ID token directly. The demos display only selected development claims and
never log or send the full token to a project backend.

The checked-in Vite development and preview servers send
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`. Configure the same response
headers on the production host; otherwise bb.js safely falls back to one proving
thread. The SDK selects up to eight available hardware threads, runs proving in
a dedicated worker, and reuses the initialized prover for the page lifetime.
The GIS button explicitly opts into FedCM so Google authentication does not
depend on cross-origin popup/opener communication while the page is isolated
on supported Chrome versions. A browser without FedCM may require a redirect or
separate authentication context; relaxing COOP to support its legacy popup flow
also disables threaded proving.

The initial flow has no paymaster. When the post-login device check shows that
authorization is required, the app generates a proof. Fund the displayed
counterfactual address with Base Sepolia ETH and authorize it before the
ten-minute proof expires. The first UserOperation deploys the account and adds
the proof-bound device; later operations use only a device signature. The
bundler adapter uses the standard ERC-4337 JSON-RPC methods.

Current caveat: the real UltraHonk validation consumes about 754k gas in the
fixture and direct account creation about 888k gas. Strict ERC-7562 bundlers
commonly cap verification gas at 500k and may reject the external Google-key
registry storage read. This deployed MVP therefore needs a bundler with relaxed
validation policy until verification moves to a supported aggregator or is
reduced below standard limits. This is not production bundler compatibility.

Both demos use discoverable WebAuthn passkeys with required user verification.
When the provider supports the PRF extension, each app domain-separates its PRF
output and derives the secp256k1 device key only in memory. When PRF is not
available, the SDK generates a random device key that remains in memory only and
is never written to localStorage or IndexedDB. Reloading the page loses that key,
so a new key requires another Google proof before it can be authorized.

After Google login, the demos derive the deterministic account address locally
and check whether the current device key is already authorized. They initialize
the prover and generate a proof only when device authorization is required.

## Exact protocol encodings

The GIS nonce is lowercase `0x`-prefixed SHA-256 of:

```text
UTF8("GOOGLE_4337_LOGIN_V1")
|| uint256_be(chainId)
|| address(factory)              // 20 bytes
|| address(deviceKey)            // 20 bytes
|| uint64_be(proofExpiry)
|| bytes32(loginRandomness)
```

The account treats the Ethereum address as the operational device-key
identifier. `proofExpiry` is generated as current browser time plus ten minutes.
The circuit proves the JWT nonce equals this digest and that `JWT.exp` is at
least `proofExpiry`; the validator enforces `proofExpiry` again onchain.

The Google key commitment starts as SHA-256 of:

```text
UTF8("GOOGLE_RSA_KEY_V1")
|| uint16_be(modulusLength) || modulus_be
|| uint16_be(exponentLength) || exponent_be
```

It is encoded as a Noir-safe field element by zeroing the digest's highest byte
(retaining the low 248 bits). Public audience hashes must use the same low-248
SHA-256 convention. This avoids accidentally passing an out-of-field `bytes32`
to the generated verifier.

Google proof public inputs have this fixed order:

```text
0 identityCommitment
1 audienceHash
2 deviceAddress (left-zero-padded)
3 chainId
4 factoryAddress (left-zero-padded)
5 validUntil
6 googleKeyHash
```

`audienceHash` is low-248 SHA-256 of the normalized UTF-8 `aud`, encoded as
`0x00 || digest[1..31]`. The deterministic fixture is executed by Noir and the
same encoding is implemented in TypeScript and the JWK import script.

## Threat model

### What the current proof establishes

- Google signed an OIDC token for a particular hidden `sub`.
- Its issuer, audience, expiry, algorithm, and nonce satisfy protocol policy.
- The nonce authorized a specific passkey-derived device key for this chain and
  factory.
- The same hidden Google identity deterministically maps to the same account.

The circuit currently accepts only compact JSON claim encodings, a single string
`aud`, RS256, 2048-bit RSA moduli, exponent 65537, headers up to 96 bytes,
payloads up to 735 bytes, audiences up to 128 bytes, and subjects up to 64
bytes. The browser rejects tokens outside those explicit MVP bounds.

### What remains trusted

- Google and Google's account recovery/security;
- Google, Chainlink CRE/DON execution, and the configured Keystone forwarder
  and workflow-owner identity for Google JWK rotation;
- frontend JavaScript integrity;
- the selected bundler/paymaster infrastructure;
- circuit and generated-verifier correctness;
- the configured EntryPoint and factory deployment.

### What is not intended to be trusted

No project backend should receive the JWT, attest Google ownership, hold user
keys, sign UserOperations, or custody the account. A dapp should not gain wallet
authority merely by integrating the SDK.

## Remaining milestones

1. Configure a relaxed-policy Base Sepolia bundler and execute the first live
   bootstrap and device-signed UserOperations.
2. Demonstrate the exact same account from fresh Demo A and Demo B origins, then
   exercise device/audience revocation.
3. Reduce validation gas and external-storage dependencies for strict ERC-7562
   bundler compatibility.

Never commit real ID tokens, OAuth secrets, device keys, or prover inputs derived
from a live token.
