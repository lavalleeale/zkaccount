import assert from "node:assert/strict";
import { resolveDemoARoute } from "../src/routing";

assert.equal(resolveDemoARoute("/", ""), "/");
assert.equal(resolveDemoARoute("/", "?rpId=wallet.example"), "/authorize");
assert.equal(resolveDemoARoute("/", "?chainId=84532"), "/authorize");
assert.equal(resolveDemoARoute("/authorize/", ""), "/authorize");
assert.equal(resolveDemoARoute("/devices", ""), "/devices");
assert.equal(resolveDemoARoute("/unknown", ""), "/");
