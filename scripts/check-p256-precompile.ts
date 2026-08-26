const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100";
const vector = [
  "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
  "0000000000000000000000000000000000000000000000000000000000000005",
  "0000000000000000000000000000000000000000000000000000000000000001",
  "a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
  "5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
].join("");

const networks = [
  {
    name: "Base Sepolia",
    url: process.env.BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org",
  },
  {
    name: "Ethereum Sepolia",
    url: process.env.ETHEREUM_SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
  },
];

async function main() {
  for (const [index, network] of networks.entries()) {
    const response = await fetch(network.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: index + 1,
        method: "eth_call",
        params: [{ to: P256_PRECOMPILE, data: `0x${vector}` }, "latest"],
      }),
    });
    if (!response.ok) throw new Error(`${network.name} RPC returned HTTP ${response.status}`);
    const body = (await response.json()) as {
      result?: string;
      error?: { code: number; message: string };
    };
    if (body.error) {
      throw new Error(
        `${network.name} eth_call failed (${body.error.code}): ${body.error.message}`,
      );
    }
    if (body.result !== `0x${"0".repeat(63)}1`) {
      throw new Error(
        `${network.name} does not expose a compatible P-256 precompile at ${P256_PRECOMPILE}`,
      );
    }
    process.stdout.write(`${network.name}: P-256 precompile available\n`);
  }
}

void main();
