import { createHash } from "node:crypto";

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const KEY_DOMAIN = Buffer.from("GOOGLE_RSA_KEY_V1", "utf8");

interface GoogleJwk {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function lengthPrefix(value: Buffer): Buffer {
  if (value.length > 0xffff) throw new Error("JWK component is too long");
  const length = Buffer.alloc(2);
  length.writeUInt16BE(value.length);
  return Buffer.concat([length, value]);
}

// This exact SHA-256 commitment must also be constrained in the Noir circuit.
// Domain || uint16_be(n.length) || n || uint16_be(e.length) || e.
export function googleKeyHash(modulus: Buffer, exponent: Buffer): `0x${string}` {
  const digest = createHash("sha256")
    .update(Buffer.concat([KEY_DOMAIN, lengthPrefix(modulus), lengthPrefix(exponent)]))
    .digest();
  // Noir public inputs are BN254 scalar fields. Keeping the low 248 bits is
  // unambiguous, always field-safe, and still provides ample collision margin.
  digest[0] = 0;
  return `0x${digest.toString("hex")}`;
}

async function main() {
  const response = await fetch(GOOGLE_JWKS_URL);
  if (!response.ok) throw new Error(`Google JWKS request failed: ${response.status}`);
  const body = (await response.json()) as { keys: GoogleJwk[] };
  const keys = body.keys
    .filter((key) => key.kty === "RSA" && key.alg === "RS256" && key.use === "sig")
    .map((key) => {
      const modulus = fromBase64Url(key.n);
      const exponent = fromBase64Url(key.e);
      const keyHash = googleKeyHash(modulus, exponent);
      return {
        kid: key.kid,
        modulusHex: `0x${modulus.toString("hex")}`,
        exponentHex: `0x${exponent.toString("hex")}`,
        keyHash,
      };
    });
  process.stdout.write(`${JSON.stringify({ source: GOOGLE_JWKS_URL, keys }, null, 2)}\n`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
