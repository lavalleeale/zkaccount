# zkAccount

**Recover the same ERC-4337 smart account from any app with Google—without revealing the Google account onchain or trusting an application backend.**

zkAccount is a Sepolia-testnet MVP for portable smart accounts, deployed on both Base Sepolia and Ethereum Sepolia. A Google ID token is verified inside a Noir zero-knowledge circuit in the browser. The resulting proof resolves a deterministic account and authorizes an app-specific, passkey-derived device key. After that one-time bootstrap, normal transactions use the device key and do not require another Google proof.

The repository includes the complete path: two independent demo apps, browser proving, an SDK, ERC-4337 contracts, the generated UltraHonk verifier, legacy Base Sepolia deployment metadata, and a Chainlink CRE workflow for Google key rotation.

> **MVP status:** account derivation, browser proof generation, contract verification, device authorization, and UserOperation construction are implemented and tested. Live end-to-end transactions require an EntryPoint v0.8 bundler for the selected network. See [MVP constraints](#mvp-constraints).

## The demo

The two apps deliberately share no browser state:

1. **Demo A** creates or unlocks a passkey, authenticates with Google, generates a ZK proof locally, and authorizes Demo A's device key.
2. **Demo B** repeats the flow from a separate origin, then acts as a Base Sepolia or Ethereum Sepolia web wallet for AppKit and other WalletConnect dapps.
3. Both apps derive the **same smart-account address** from the same private Google identity.
4. Either authorized device can send an ERC-4337 transaction, manage devices, or revoke itself. Demo A can also manage approved Google OAuth audiences.

This demonstrates identity portability without exporting a seed phrase, sharing local storage, or sending the Google JWT to a project server.

```mermaid
flowchart LR
    G["Google ID token"] --> P["Browser Noir prover"]
    P -->|"private: subject + JWT"| Z["UltraHonk proof"]
    Z --> A["Deterministic ERC-4337 account"]
    DA["Demo A passkey key"] --> A
    DB["Demo B passkey key"] --> A
    A --> U["Device-signed UserOperations"]
```

## What the MVP proves

- Google signed an RS256 OIDC token for a hidden `sub`.
- The token has the expected issuer, algorithm, audience, nonce, issued-at time, and expiry.
- The nonce binds authorization to one device address, chain, factory, and ten-minute proof window.
- The private Google identity maps to the same Poseidon2 commitment—and therefore the same CREATE2 account—across independent apps.
- The signing key belongs to the CRE-managed set of current Google JWKs.

Only eight field elements are public: the identity commitment, audience hash, device address, chain ID, factory address, authorization expiry, Google key commitment, and the JWT issued-at time used as the account's monotonic Google nonce. The JWT and Google subject remain private.

## Run the MVP

### 1. Install the toolchain

[Nix](https://nixos.org/) is the easiest path because the flake pins Node.js 22, Foundry, Nargo `1.0.0-beta.26`, Barretenberg `5.2.0`, Bun, and the CRE CLI.

```sh
nix develop
npm install
```

Without Nix, install Node.js 22+ and use the pinned Nargo and Barretenberg versions above. Foundry is only required for Solidity tests.

### 2. Configure the demo origins

Use the project's audience-matched Google OAuth web client, or deploy a factory with your own root Google OAuth client ID. The factory derives its `rootAudience` as the low-248 SHA-256 hash of that client ID. Allow both local origins on that client:

- `http://localhost:5173` for Demo A
- `http://localhost:5174` for Demo B

Then configure each app:

```sh
cp apps/demo-a/.env.example apps/demo-a/.env.local
cp apps/demo-b/.env.example apps/demo-b/.env.local
```

```dotenv
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
VITE_BASE_SEPOLIA_FACTORY=your-base-sepolia-factory
VITE_BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
VITE_BASE_SEPOLIA_BUNDLER_URL=https://your-base-sepolia-bundler.example/rpc
VITE_ETHEREUM_SEPOLIA_FACTORY=your-ethereum-sepolia-factory
VITE_ETHEREUM_SEPOLIA_FACTORY_DEPLOYMENT_BLOCK=11567335
VITE_ETHEREUM_SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
VITE_ETHEREUM_SEPOLIA_BUNDLER_URL=https://your-ethereum-sepolia-bundler.example/rpc
# Demo B only: create a wallet project at https://dashboard.walletconnect.com
VITE_REOWN_PROJECT_ID=your-walletconnect-project-id
```

The current eight-input, `iat`-backed protocol requires a fresh deployment. The legacy factory recorded in `deployments/base-sepolia.json` is permanently bound to its original account bytecode and seven-input verifier and is not compatible with the current SDK. A custom OAuth client also requires a correspondingly configured deployment. The bundler must support EntryPoint v0.8.

### 3. Start both independent apps

```sh
npm run dev:a
```

```sh
npm run dev:b
```

Open both URLs, choose the same network in each, create a distinct passkey in each app, and authenticate with the same Google account. Account prediction and local proof generation work without a bundler. To authorize a device onchain, fund the displayed counterfactual address with the selected network's Sepolia ETH before the ten-minute proof expires, then submit the bootstrap UserOperation.

After authorization, Demo B stores only the public account address, factory, and chain ID. On a return visit, unlocking the same passkey re-derives the device key and checks its onchain authorization without requiring Google again. Private keys, Google tokens, proofs, and PRF output remain memory-only.

To use Demo B as a wallet, open an AppKit dapp's WalletConnect flow and configure Demo B as a custom web wallet with the URL `http://localhost:5174/wc`. AppKit opens `?uri=wc:...`; Demo B also accepts a copied WalletConnect URI manually. It advertises only the currently selected chain—Base Sepolia (`eip155:84532`) or Ethereum Sepolia (`eip155:11155111`)—and supports `eth_sendTransaction`, `personal_sign`, and `eth_signTypedData_v4`. Disconnect active sessions before changing networks. Every connection and request requires explicit approval, and signing requires the passkey to be unlocked.

## How it works

### Browser and SDK

`@zkaccount/sdk` handles Google Identity Services, nonce construction, passkey PRF key derivation, identity commitments, threaded bb.js proving, account prediction, and EntryPoint v0.8 UserOperations. Demo B uses Reown WalletKit for encrypted WalletConnect sessions and request delivery. The full ID token stays in the page and is never logged or sent to a zkAccount backend.

PRF-capable passkeys deterministically derive an app-scoped secp256k1 device key in memory. If the authenticator does not support PRF, the SDK falls back to a random memory-only key that is lost on reload and must be authorized again.

### Circuit

The Noir circuit reconstructs the JWT signing input, verifies the 2048-bit RSA/PKCS#1 v1.5 SHA-256 signature, checks the OIDC claims and login nonce, exposes the signed `iat` as a monotonic Google authorization nonce, derives a private Poseidon2 identity commitment, and commits to the Google RSA key. The generated Solidity UltraHonk verifier is tested against a real fixture proof.

The eight public inputs are ordered as identity commitment, audience hash, device address, chain ID, factory address, authorization expiry, Google key commitment, and `iat`-backed Google nonce.

### Smart account

`GoogleAccountFactory` deterministically deploys one account per identity commitment. `GoogleAccount` supports two ERC-4337 signature modes:

- `0x01`: a short-lived Google proof that can execute exactly one `addDevice(proofBoundDevice)` self-call;
- `0x00`: a low-s secp256k1 signature from an authorized device for subsequent operations.

The account also implements ERC-1271. Personal-message and EIP-712 requests return a canonical device signature that `isValidSignature` accepts only while that device remains authorized. Demo B does not advertise raw transaction signing, WalletConnect-driven chain switching, or batch calls; its local selector chooses one supported Sepolia network at a time.

Anyone may deploy a counterfactual account, but deployment grants no authority. Racing `createAccount(identity)` cannot install an attacker's key.

Each account consumes a strictly increasing Google nonce during validation. If two Google logins carry the same one-second `iat`, only the first can authorize a device; the SDK asks the loser to sign in again for a fresh authorization.

### Google key rotation

Google's signing keys are not manually administered. The scheduled Chainlink CRE workflow fetches Google's JWKS independently across DON nodes, requires identical normalized results, and atomically replaces the onchain key set through the authenticated Keystone forwarder. Keys absent from the new report are revoked.

## Repository map

| Path                                    | Purpose                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `apps/demo-a`                           | Primary React/Vite onboarding, transaction, device, and audience demo    |
| `apps/demo-b`                           | Dual-Sepolia independent-origin recovery and WalletConnect web wallet    |
| `packages/sdk`                          | Browser auth/proving, passkeys, account helpers, and ERC-4337 client     |
| `circuits/google_jwt`                   | Noir JWT/RS256 authorization circuit and generated artifacts             |
| `contracts/src`                         | Account, factory, policy validator, key registry, and generated verifier |
| `contracts/test`                        | Foundry policy tests plus real-proof verifier fixtures                   |
| `cre/google-jwks`                       | Scheduled Chainlink CRE Google JWKS consensus workflow                   |
| `deployments/base-sepolia-current.json` | Current ERC-1271/WalletKit-compatible Base Sepolia deployment metadata   |
| `deployments/ethereum-sepolia.json`     | Current ERC-1271/WalletKit-compatible Ethereum Sepolia deployment        |
| `deployments/base-sepolia.json`         | Legacy, current-artifact-incompatible Base Sepolia deployment metadata   |

## Deploy the current contract stack

The ERC-1271 account bytecode changes every counterfactual account address, so the wallet-enabled demos require a fresh factory. The deployment script simulates by default and broadcasts only when `--broadcast` is explicitly supplied.

```sh
export ENTRY_POINT=0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108
export ROOT_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export CRE_FORWARDER=0x...
export CRE_WORKFLOW_OWNER=0x...

# Read-only simulation
forge script contracts/script/Deploy.s.sol:Deploy --rpc-url https://sepolia.base.org --sender 0x... -vvv

# Intentional live deployment
forge script contracts/script/Deploy.s.sol:Deploy --rpc-url "$BASE_SEPOLIA_RPC_URL" --account your-keystore --sender 0x... --broadcast -vvv
```

The current deployment was broadcast at Base Sepolia block `45965274`:

| Contract                | Current address                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| GoogleAccountFactory    | [`0xfFc6dFC1218bf0AA8B759c543DF2F81eF07A34B0`](https://sepolia.basescan.org/address/0xfFc6dFC1218bf0AA8B759c543DF2F81eF07A34B0) |
| GoogleJWTValidator      | [`0xDaDBB1130aE516E36Fe7021111462BFE630e98fb`](https://sepolia.basescan.org/address/0xDaDBB1130aE516E36Fe7021111462BFE630e98fb) |
| GeneratedGoogleVerifier | [`0x0370D2FE5b1d42f00Fac4132Fd8606607Ccc55d7`](https://sepolia.basescan.org/address/0x0370D2FE5b1d42f00Fac4132Fd8606607Ccc55d7) |
| GoogleKeyRegistry       | [`0x6722F177B0E58A94f7B937B8319d6EBA300e16fA`](https://sepolia.basescan.org/address/0x6722F177B0E58A94f7B937B8319d6EBA300e16fA) |

The CRE workflow simulation fetched and encoded four Google signing keys. A dry-run simulation does not mutate the registry, but running the simulator with `--broadcast` published those four key commitments through the configured Base Sepolia mock forwarder. The current registry therefore supports Google bootstrap transactions without CRE workflow deployment access. This is a testnet simulation setup, not a production DON deployment. See `deployments/base-sepolia-current.json` for deployment transaction hashes and simulation hashes.

The Ethereum Sepolia deployment was broadcast at block `11567335`:

| Contract                | Current address                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| GoogleAccountFactory    | [`0x277A014915F95d6f83323435f6822A11DB1a2Cbb`](https://sepolia.etherscan.io/address/0x277A014915F95d6f83323435f6822A11DB1a2Cbb) |
| GoogleJWTValidator      | [`0x3a1fcFfBa1Ec75c6389b2eB729Cd7B42A6f4C21B`](https://sepolia.etherscan.io/address/0x3a1fcFfBa1Ec75c6389b2eB729Cd7B42A6f4C21B) |
| GeneratedGoogleVerifier | [`0x534837ce36F46b664A0155D00E79C58B8868F3B0`](https://sepolia.etherscan.io/address/0x534837ce36F46b664A0155D00E79C58B8868F3B0) |
| GoogleKeyRegistry       | [`0xE95dc39142c5043c7f3Dc530C899Cb9b62910bE2`](https://sepolia.etherscan.io/address/0xE95dc39142c5043c7f3Dc530C899Cb9b62910bE2) |

The Ethereum Sepolia registry contains the same four Google key commitments, published by the local CRE simulator through the official mock forwarder. Full addresses and transaction hashes are recorded in `deployments/ethereum-sepolia.json`.

For a future deployment, record the emitted addresses after broadcast, set the new factory in both demos, configure the CRE workflow for the new registry, and populate the registry before attempting Google bootstrap. Never commit the deployer key or live OAuth credentials.

## Legacy Base Sepolia deployment

The addresses below predate the `iat`-backed Google nonce and are retained as historical deployment metadata. Do not configure the current demos with this factory; deploy the current verifier, validator, registry, and factory stack first.

| Contract                | Address                                                                                                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| EntryPoint v0.8         | [`0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`](https://sepolia.basescan.org/address/0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108) |
| GoogleAccountFactory    | [`0x5C567AbFc1805094943A7F153381EB38845580B6`](https://sepolia.basescan.org/address/0x5C567AbFc1805094943A7F153381EB38845580B6) |
| GoogleJWTValidator      | [`0x6665ee4A35417306C0D37F80B694DdDEc53E1723`](https://sepolia.basescan.org/address/0x6665ee4A35417306C0D37F80B694DdDEc53E1723) |
| GeneratedGoogleVerifier | [`0x28D6a6FECd61864Ee00C9C44Ac607A31b13Ed52f`](https://sepolia.basescan.org/address/0x28D6a6FECd61864Ee00C9C44Ac607A31b13Ed52f) |
| GoogleKeyRegistry       | [`0xb17650A640EdA09E9A36AF3bb6ac1e28Da5A3D34`](https://sepolia.basescan.org/address/0xb17650A640EdA09E9A36AF3bb6ac1e28Da5A3D34) |

Deployment metadata, including transaction hashes and the configured root audience, lives in [`deployments/base-sepolia.json`](deployments/base-sepolia.json).

## Verify the repository

Run the full local validation suite from the Nix development shell:

```sh
forge test -vv
npm run circuit:fixture
npm run circuit:test-negative
npm run circuit:generate-verifier
npm run circuit:test-bbjs
npm run sdk:test
npm test -w @zkaccount/demo-b
npm run typecheck
npm ci --prefix cre/google-jwks
npm run typecheck:cre
npm run build
```

The circuit currently expands to 262,021 Barretenberg gates, just below the 2^18 proving-domain boundary. Set `BBJS_THREADS` to benchmark a specific worker count.

## Security model

The system still trusts Google account security, Google and the configured CRE/DON path for key rotation, frontend integrity, the selected ERC-4337 infrastructure, and the correctness of the circuit and generated verifier.

It does **not** require a project backend to receive the JWT, attest account ownership, custody keys, or sign UserOperations. Integrating an app also does not automatically grant that app authority over the account.

The circuit intentionally accepts a constrained MVP subset: compact JSON claims, a single string `aud`, RS256, 2048-bit RSA with exponent 65537, headers up to 96 bytes, payloads up to 735 bytes, audiences up to 128 bytes, and subjects up to 64 bytes.

## MVP constraints

- A fixture Google-proof validation consumes about 754k gas, and direct account creation about 888k gas.
- There is no paymaster. The counterfactual account must hold the selected network's Sepolia ETH before its first UserOperation.
- The registry starts empty and accepts bootstrap proofs only after a successful authenticated CRE report. Google key rotation can briefly precede the next scheduled six-hour update.
- Cross-origin isolation enables threaded browser proving. Production hosts must send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`; otherwise bb.js falls back to one thread.

The next milestone is a recorded live portability run across both demo origins, followed by further verifier and proving-performance optimization.

## CRE workflow

Set the deployed registry address and workflow identity in `cre/google-jwks/config.staging.json`. From the repository root inside the Nix development shell, install the workflow dependencies and run a read-only simulation:

```sh
npm ci --prefix cre/google-jwks
cre workflow simulate google-jwks \
  --project-root cre \
  --target staging-settings \
  --config config.staging.json
```

To publish the simulated report to the testnet selected in `cre/project.yaml` through its configured mock forwarder, decrypt the local Foundry keystore only for the lifetime of the command and add `--broadcast`:

```sh
CRE_ETH_PRIVATE_KEY=$(cast wallet --json decrypt-keystore zkaccount-deployer --unsafe-password "" | tail -c 67) \
  cre workflow simulate google-jwks \
    --project-root cre \
    --target staging-settings \
    --config config.staging.json \
    --broadcast
```

The `zkaccount-deployer` keystore currently has an empty password. The broadcasting account must hold enough ETH on the selected testnet for the mock-forwarder transaction. `--broadcast` changes real testnet state, but the report is produced by the local single-node simulator and must not be treated as a production DON-attested report. A production deployment must use the production Keystone forwarder and `cre workflow deploy` after deployment access is enabled.

Never commit live ID tokens, OAuth secrets, device private keys, or prover inputs derived from a real token.
