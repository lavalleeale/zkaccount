import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Barretenberg, BackendType, UltraHonkBackend } from "@aztec/bb.js";

const circuitDir = resolve(import.meta.dirname, "../google_jwt");
const artifact = JSON.parse(
  readFileSync(resolve(circuitDir, "target/google_jwt.json"), "utf8"),
) as { bytecode: string };
const witness = new Uint8Array(readFileSync(resolve(circuitDir, "target/fixture.gz")));
const threads = Number(process.env.BBJS_THREADS ?? "1");
if (!Number.isInteger(threads) || threads < 1 || threads > 32) {
  throw new Error("BBJS_THREADS must be an integer from 1 through 32");
}

async function main() {
  const api = await Barretenberg.new({
    backend: BackendType.Wasm,
    threads,
    memory: { initial: 1024, maximum: 32768 },
  });
  try {
    const backend = new UltraHonkBackend(artifact.bytecode, api);
    const proof = await backend.generateProof(witness, { verifierTarget: "evm" });
    if (!(await backend.verifyProof(proof, { verifierTarget: "evm" }))) {
      throw new Error("bb.js rejected its generated EVM proof");
    }
    process.stdout.write(
      `bb.js WASM proof verified with ${threads} thread(s): ${proof.proof.length} proof bytes, ${proof.publicInputs.length} public inputs\n`,
    );
  } finally {
    await api.destroy();
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
