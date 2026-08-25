# Generated circuit artifacts

Every tracked file in this directory is generated, intentionally committed, and fully regeneratable from the circuit source, test-only fixture keys, and repository scripts. Do not edit, replace, or delete individual artifacts by hand.

Regenerate and verify the complete artifact set from the repository root, inside the pinned Nix development environment:

```sh
npm run circuit:fixture
npm run circuit:test-negative
npm run circuit:generate-verifier
npm run circuit:test-bbjs
```

Regeneration also updates `packages/sdk/src/generated/google_jwt.json`, `contracts/src/GeneratedGoogleVerifier.sol`, and the proof fixtures in `contracts/test/fixtures`. UltraHonk proof generation uses randomness, so valid regenerated proof bytes need not be byte-identical. The negative suite may also emit additional redundant `negative_*.gz` witnesses. Review generated diffs and commit required synchronized artifacts together rather than editing any of them individually.
