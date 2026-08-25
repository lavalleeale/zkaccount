import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "../..");
const circuitDir = resolve(root, "circuits/google_jwt");
const nargo = process.env.NARGO_BIN ?? "nargo";
const bb = process.env.BB_BIN ?? "bb";
const wrapper = process.env.ZK_BIN_WRAPPER;

function run(binary: string, args: string[]): void {
  const command = wrapper ?? binary;
  const commandArgs = wrapper ? [binary, ...args] : args;
  const result = spawnSync(command, commandArgs, { cwd: circuitDir, stdio: "inherit" });
  if (result.status !== 0) throw new Error(`${binary} ${args[0]} failed`);
}

run(nargo, ["compile"]);
mkdirSync(resolve(circuitDir, "target/evm"), { recursive: true });
for (const artifact of ["target/evm/vk", "target/evm/Verifier.sol"]) {
  const path = resolve(circuitDir, artifact);
  if (existsSync(path)) rmSync(path, { recursive: true });
}
run(bb, [
  "write_vk", "-b", "target/google_jwt.json", "-o", "target/evm", "-t", "evm",
]);
run(bb, [
  "write_solidity_verifier", "-k", "target/evm/vk", "-o", "target/evm/Verifier.sol",
  "-t", "evm", "--optimized",
]);

const generated = readFileSync(resolve(circuitDir, "target/evm/Verifier.sol"), "utf8")
  .replace("contract HonkVerifier is IVerifier", "contract GeneratedGoogleVerifier is IVerifier");
writeFileSync(resolve(root, "contracts/src/GeneratedGoogleVerifier.sol"), generated);
writeFileSync(
  resolve(root, "packages/sdk/src/generated/google_jwt.json"),
  readFileSync(resolve(circuitDir, "target/google_jwt.json")),
);
process.stdout.write("Updated Solidity verifier and browser circuit artifact\n");
