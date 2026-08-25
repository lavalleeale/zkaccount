import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "../..");
const circuitDir = resolve(root, "circuits/google_jwt");
const proverPath = resolve(circuitDir, "Prover.toml");
const generator = resolve(root, "circuits/scripts/generate-fixture.ts");
const tsx = resolve(root, "node_modules/.bin/tsx");
const nargo = process.env.NARGO_BIN ?? "nargo";
const wrapper = process.env.NARGO_WRAPPER;

function generate(variant?: string): string {
  const result = spawnSync(tsx, variant ? [generator, variant] : [generator], { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return readFileSync(proverPath, "utf8");
}

function mutateArray(toml: string, key: string, mutate: (values: string[]) => void): string {
  const pattern = new RegExp(`^${key} = \\[(.*)\\]$`, "m");
  const match = toml.match(pattern);
  if (!match) throw new Error(`Missing ${key}`);
  const values = match[1].split(", ");
  mutate(values);
  return toml.replace(pattern, `${key} = [${values.join(", ")}]`);
}

function executeShouldFail(name: string, toml: string): void {
  writeFileSync(proverPath, toml);
  const args = wrapper ? [nargo, "execute", `negative_${name}`] : ["execute", `negative_${name}`];
  const result = spawnSync(wrapper ?? nargo, args, { cwd: circuitDir, encoding: "utf8" });
  if (result.status === 0) throw new Error(`${name}: invalid witness unexpectedly succeeded`);
  process.stdout.write(`PASS negative ${name}\n`);
}

const valid = generate();

executeShouldFail("expired", generate("expired"));
executeShouldFail("wrong_alg", generate("wrong_alg"));
executeShouldFail("wrong_issuer_signed", generate("wrong_issuer"));

executeShouldFail("subject", mutateArray(valid, "subject", (values) => {
  values[0] = values[0] === '"0x31"' ? '"0x32"' : '"0x31"';
}));
executeShouldFail("audience", mutateArray(valid, "audience", (values) => {
  values[0] = values[0] === '"0x66"' ? '"0x67"' : '"0x66"';
}));
executeShouldFail("nonce", mutateArray(valid, "login_randomness", (values) => {
  values[0] = '"0xff"';
}));
executeShouldFail("signature", mutateArray(valid, "signature_limbs", (values) => {
  values[0] = `"0x${(BigInt(values[0].slice(1, -1)) + 1n).toString(16)}"`;
}));
executeShouldFail("google_key", mutateArray(valid, "modulus_bytes", (values) => {
  values[0] = `"0x${(BigInt(values[0].slice(1, -1)) ^ 1n).toString(16)}"`;
}));
executeShouldFail("issuer", mutateArray(valid, "payload", (values) => {
  // {"iss":"h... — mutate the first issuer byte while preserving claim offsets.
  values[8] = '"0x69"';
}));
executeShouldFail("signed_payload", mutateArray(valid, "payload", (values) => {
  const bytes = values.map((value) => Number(BigInt(value.slice(1, -1))));
  const marker = Buffer.from('"iat":1999999700');
  const index = Buffer.from(bytes).indexOf(marker);
  if (index < 0) throw new Error("iat marker missing");
  values[index + 6] = '"0x32"';
}));
executeShouldFail("public_identity", mutateArray(valid, "return", (values) => {
  values[0] = `"0x${(BigInt(values[0].slice(1, -1)) + 1n).toString(16)}"`;
}));

generate();
