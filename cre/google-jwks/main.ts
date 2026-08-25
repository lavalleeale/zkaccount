import {
  CronCapability,
  EVMClient,
  HTTPClient,
  type HTTPSendRequester,
  Runner,
  TxStatus,
  consensusIdenticalAggregation,
  getNetwork,
  handler,
  json,
  ok,
  prepareReportRequest,
  type Runtime,
} from "@chainlink/cre-sdk";
import {
  type Address,
  encodeAbiParameters,
  sha256,
  toHex,
} from "viem";
import { z } from "zod";

const configSchema = z.object({
  schedule: z.string(),
  googleJwksUrl: z.string().refine((value) => value.startsWith("https://"), {
    message: "Google JWKS URL must use HTTPS",
  }),
  evm: z.object({
    chainSelectorName: z.string(),
    registryAddress: z.string(),
  }),
});

type Config = z.infer<typeof configSchema>;

interface GoogleJwk {
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

const KEY_DOMAIN = new Uint8Array([
  71, 79, 79, 71, 76, 69, 95, 82, 83, 65, 95, 75, 69, 89, 95, 86, 49,
]);
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const result = new Uint8Array(Math.floor((base64.length * 6) / 8));
  let accumulator = 0;
  let bits = 0;
  let offset = 0;

  for (const character of base64) {
    const digit = BASE64_ALPHABET.indexOf(character);
    if (digit < 0) throw new Error("Invalid Base64URL value in Google JWK");
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      result[offset++] = (accumulator >> bits) & 0xff;
    }
  }
  return result;
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff) throw new Error("JWK component is too long");
  return new Uint8Array([value.length >> 8, value.length & 0xff]);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function keyCommitment(key: GoogleJwk): `0x${string}` {
  const modulus = fromBase64Url(key.n);
  const exponent = fromBase64Url(key.e);
  const digest = sha256(
    toHex(
      concat([
        KEY_DOMAIN,
        lengthPrefix(modulus),
        modulus,
        lengthPrefix(exponent),
        exponent,
      ]),
    ),
  );
  return `0x00${digest.slice(4)}`;
}

function fetchKeySet(sendRequester: HTTPSendRequester, config: Config): string {
  const response = sendRequester
    .sendRequest({ url: config.googleJwksUrl, method: "GET" })
    .result();
  if (!ok(response)) {
    throw new Error(`Google JWKS request failed with status ${response.statusCode}`);
  }

  const body = json(response) as { keys?: GoogleJwk[] };
  const commitments = (body.keys ?? [])
    .filter((key) => key.kty === "RSA" && key.alg === "RS256" && key.use === "sig")
    .map(keyCommitment)
    .sort();

  if (commitments.length === 0 || commitments.length > 16) {
    throw new Error(`Unexpected Google signing key count: ${commitments.length}`);
  }
  if (new Set(commitments).size !== commitments.length) {
    throw new Error("Google JWKS contains duplicate signing keys");
  }
  return JSON.stringify(commitments);
}

function onCronTrigger(runtime: Runtime<Config>) {
  const serializedKeySet = new HTTPClient()
    .sendRequest(runtime, fetchKeySet, consensusIdenticalAggregation<string>())(
      runtime.config,
    )
    .result();
  const keys = JSON.parse(serializedKeySet) as `0x${string}`[];

  const network = getNetwork({
    chainFamily: "evm",
    chainSelectorName: runtime.config.evm.chainSelectorName,
    isTestnet: true,
  });
  if (!network) throw new Error("Configured EVM network is not supported by CRE");

  const reportPayload = encodeAbiParameters(
    [{ name: "keys", type: "bytes32[]" }],
    [keys],
  );
  const report = runtime.report(prepareReportRequest(reportPayload)).result();
  const response = new EVMClient(network.chainSelector.selector)
    .writeReport(runtime, {
      receiver: runtime.config.evm.registryAddress as Address,
      report,
      gasConfig: { gasLimit: "500000" },
    })
    .result();

  if (response.txStatus !== TxStatus.SUCCESS) {
    throw new Error(`CRE report write failed: ${response.errorMessage || response.txStatus}`);
  }
  runtime.log(`Updated Google key registry with ${keys.length} keys`);
  return keys.length;
}

const initWorkflow = (config: Config) => [
  handler(new CronCapability().trigger({ schedule: config.schedule }), onCronTrigger),
];

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema });
  await runner.run(initWorkflow);
}
