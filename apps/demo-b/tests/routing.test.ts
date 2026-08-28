import assert from "node:assert/strict";
import { resolveDemoBRoute, walletCompletionCopy } from "../src/routing";

assert.equal(resolveDemoBRoute("/"), "/");
assert.equal(resolveDemoBRoute("/wallet/"), "/wallet");
assert.equal(resolveDemoBRoute("/connections"), "/connections");
assert.equal(resolveDemoBRoute("/wc"), "/wc");
assert.equal(resolveDemoBRoute("/unknown"), "/");
assert.equal(
  walletCompletionCopy({ outcome: "rejected", kind: "session_request", returnUrl: "" }).detail,
  "No passkey signature was created.",
);
assert.equal(
  walletCompletionCopy({ outcome: "approved", kind: "session_proposal", returnUrl: "" }).title,
  "Dapp connected.",
);
