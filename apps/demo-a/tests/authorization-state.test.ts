import assert from "node:assert/strict";
import {
  authorizationCompletionCopy,
  authorizationStep,
  resolveAuthorizationPhase,
} from "../src/authorization-state";

const initial = {
  hasDevice: false,
  hasLogin: false,
  hasProof: false,
  authorized: false,
  pending: false,
  complete: false,
  signingIn: false,
};

assert.equal(resolveAuthorizationPhase(initial), "review");
assert.equal(resolveAuthorizationPhase({ ...initial, hasDevice: true }), "google");
assert.equal(resolveAuthorizationPhase({ ...initial, hasLogin: true }), "prove");
assert.equal(resolveAuthorizationPhase({ ...initial, hasProof: true }), "authorize");
assert.equal(resolveAuthorizationPhase({ ...initial, pending: true }), "authorize");
assert.equal(resolveAuthorizationPhase({ ...initial, authorized: true }), "authorize");
assert.equal(resolveAuthorizationPhase({ ...initial, complete: true }), "done");
assert.equal(resolveAuthorizationPhase({ ...initial, authorized: true, complete: true }), "done");
assert.equal(authorizationStep("prove"), 2);
assert.equal(authorizationCompletionCopy("approved").mark, "✓");
assert.equal(authorizationCompletionCopy("rejected").title, "Authorization rejected");
assert.equal(authorizationCompletionCopy("failed").title, "Authorization failed");
