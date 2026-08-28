export type DemoBRoute = "/" | "/wallet" | "/connections" | "/request" | "/complete" | "/wc";

export interface WalletCompletion {
  outcome: "approved" | "rejected";
  kind: "session_proposal" | "session_request";
  returnUrl: string;
}

const routes: DemoBRoute[] = ["/", "/wallet", "/connections", "/request", "/complete", "/wc"];

export function resolveDemoBRoute(pathname: string): DemoBRoute {
  const normalized = pathname.length > 1 ? pathname.replace(/\/$/, "") : pathname;
  return routes.includes(normalized as DemoBRoute) ? (normalized as DemoBRoute) : "/";
}

export function walletCompletionCopy(completion: WalletCompletion): {
  title: string;
  description: string;
  detail: string;
} {
  if (completion.outcome === "rejected") {
    return completion.kind === "session_proposal"
      ? {
          title: "Connection rejected.",
          description: "The dapp was not connected to your wallet.",
          detail: "No account access was granted.",
        }
      : {
          title: "Request rejected.",
          description: "The dapp received a rejection response.",
          detail: "No passkey signature was created.",
        };
  }
  return completion.kind === "session_proposal"
    ? {
        title: "Dapp connected.",
        description: "The connection was approved and the dapp can now request signatures.",
        detail: "Every future signing request still requires separate approval.",
      }
    : {
        title: "Request approved.",
        description: "The dapp received the signed response.",
        detail: "The signature was user-verified and the passkey stayed in your authenticator.",
      };
}
