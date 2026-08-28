export type DemoARoute = "/" | "/authorize" | "/devices" | "/lab";

const routes: DemoARoute[] = ["/", "/authorize", "/devices", "/lab"];

export function resolveDemoARoute(pathname: string, search: string): DemoARoute {
  const params = new URLSearchParams(search);
  if (
    pathname === "/" &&
    ["rpId", "publicKey", "callback", "state", "chainId"].some((key) => params.has(key))
  )
    return "/authorize";
  const normalized = pathname.length > 1 ? pathname.replace(/\/$/, "") : pathname;
  return routes.includes(normalized as DemoARoute) ? (normalized as DemoARoute) : "/";
}
