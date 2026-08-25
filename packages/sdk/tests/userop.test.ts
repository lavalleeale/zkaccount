import assert from "node:assert/strict";
import { decodeAbiParameters, decodeFunctionData, getAddress, parseAbi, type Hex } from "viem";
import { addDeviceCall, googleSignature, hashGoogleAudience } from "../src/userop";

const account = getAddress("0x1111111111111111111111111111111111111111");
const device = getAddress("0x2222222222222222222222222222222222222222");
const accountAbi = parseAbi([
  "function execute(address target, uint256 value, bytes data)",
  "function addDevice(address device)",
]);

const outer = decodeFunctionData({ abi: accountAbi, data: addDeviceCall(account, device) });
assert.equal(outer.functionName, "execute");
assert.equal(outer.args[0], account);
assert.equal(outer.args[1], 0n);
const inner = decodeFunctionData({ abi: accountAbi, data: outer.args[2] });
assert.equal(inner.functionName, "addDevice");
assert.equal(inner.args[0], device);

const proof = {
  proof: "0x1234" as Hex,
  publicInputs: Array.from({ length: 7 }, (_, index) => `0x${index.toString(16).padStart(64, "0")}` as Hex),
};
const signature = googleSignature(proof);
assert.equal(signature.slice(0, 4), "0x01");
const [decodedProof, decodedInputs] = decodeAbiParameters(
  [{ type: "bytes" }, { type: "bytes32[]" }],
  `0x${signature.slice(4)}`,
);
assert.equal(decodedProof, proof.proof);
assert.deepEqual(decodedInputs, proof.publicInputs);
assert.equal(
  await hashGoogleAudience("176685232849-e7govufghrlnprcc7cuijp5eusopci5b.apps.googleusercontent.com"),
  "0x003058e40c036af1aab38e49c89e0ee26d4d7be8fd6a665f8b37bde5507223d9",
);

process.stdout.write("UserOperation encoding tests passed\n");
