export type AuthorizationPhase = "review" | "google" | "prove" | "authorize" | "done";
export type AuthorizationOutcome = "approved" | "rejected" | "failed";

export function resolveAuthorizationPhase(state: {
  hasDevice: boolean;
  hasLogin: boolean;
  hasProof: boolean;
  authorized: boolean;
  pending: boolean;
  complete: boolean;
  signingIn: boolean;
}): AuthorizationPhase {
  if (state.complete) return "done";
  if (state.pending || state.hasProof || state.authorized) return "authorize";
  if (state.hasLogin) return "prove";
  if (state.signingIn || state.hasDevice) return "google";
  return "review";
}

export function authorizationStep(phase: AuthorizationPhase): number {
  return { review: 0, google: 1, prove: 2, authorize: 3, done: 4 }[phase];
}

export function authorizationCompletionCopy(outcome: AuthorizationOutcome): {
  title: string;
  description: string;
  mark: string;
} {
  if (outcome === "rejected") {
    return {
      title: "Authorization rejected",
      description: "No passkey was authorized. Return to the requesting app to continue.",
      mark: "×",
    };
  }
  if (outcome === "failed") {
    return {
      title: "Authorization failed",
      description: "The requesting app will receive the error and can start a fresh request.",
      mark: "!",
    };
  }
  return {
    title: "Authorization complete",
    description:
      "The requesting app will independently verify this device onchain before saving the wallet.",
    mark: "✓",
  };
}
