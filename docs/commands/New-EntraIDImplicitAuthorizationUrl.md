# New-EntraIDImplicitAuthorizationUrl

## Synopsis

Builds an Entra OAuth 2.0 implicit-flow authorization URL and returns both the URL and the state value needed to validate the redirect.

## Syntax

```powershell
New-EntraIDImplicitAuthorizationUrl -TenantId <string> -ClientId <string> `
  -RedirectUri <string> -Scope <string> [-State <string>] [-IncludeIdToken]
```

## Prerequisites and Entra setup

Implicit flow is a compatibility feature. For new interactive applications, use authorization code flow with PKCE instead, because implicit flow returns tokens in the browser URL fragment.

To use it:

1. Register a public-client or SPA application in Entra.
2. Add the exact `RedirectUri` to the registration's platform redirect URIs. The scheme, host, path, and trailing slash must match.
3. Enable access-token implicit grant in the registration's authentication settings. If requesting an ID token, enable ID-token implicit grant as well.
4. Configure delegated API permissions and consent for the supplied scopes.

The command only constructs the URL. It does not open a browser, start a listener, or store state.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `TenantId` | Yes | Tenant GUID/domain/selector used in the v2 `/authorize` endpoint. |
| `ClientId` | Yes | Application/client ID of the interactive application. |
| `RedirectUri` | Yes | Exact registered redirect URI that receives the fragment response. |
| `Scope` | Yes | Space-delimited delegated scopes, for example `https://graph.microsoft.com/User.Read`. |
| `State` | No | Caller-provided correlation/CSRF value. If omitted, the command generates a random GUID without dashes. Preserve the returned value and pass it to `ConvertFrom-EntraIDImplicitRedirect`. |
| `IncludeIdToken` | No | Requests both an access token and ID token (`response_type=token id_token`). The command ensures `openid` is included, always adds a random nonce, and returns it as `Nonce`. |

## Examples

Generate a URL and preserve the generated state:

```powershell
$request = New-EntraIDImplicitAuthorizationUrl `
  -TenantId 'organizations' `
  -ClientId '11111111-2222-3333-4444-555555555555' `
  -RedirectUri 'https://app.example/callback' `
  -Scope 'https://graph.microsoft.com/User.Read'

$request.AuthorizationUrl
# Open this URL in the interactive user's browser.
$request.State
```

Request an explicit state and an ID token too:

```powershell
$request = New-EntraIDImplicitAuthorizationUrl `
  -TenantId $tenantId -ClientId $clientId `
  -RedirectUri 'http://localhost:8400/callback' `
  -Scope 'https://graph.microsoft.com/User.Read profile' `
  -State $csrfState -IncludeIdToken
```

## Request behavior and output

The returned object contains:

| Property | Meaning |
| --- | --- |
| `AuthorizationUrl` | URL to the v2 authorization endpoint. It contains URL-encoded `client_id`, `redirect_uri`, `scope`, `state`, `response_mode=fragment`, and response type. |
| `State` | The supplied or generated state value. |
| `Nonce` | The generated nonce when `IncludeIdToken` was used; otherwise null. Validate the returned ID token's `nonce` claim against it. |

Normal requests use `response_type=token`. With `IncludeIdToken`, the response type is `token id_token`, `openid` is appended to the scopes when necessary, and a random `nonce` is always included and returned in the `Nonce` property. After authentication, Entra redirects to the registered URI with the result after `#`; browsers do not send that fragment to a server automatically. Pass the complete final browser URL to `ConvertFrom-EntraIDImplicitRedirect`.

## Errors and troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| Entra reports a redirect URI mismatch | Register precisely the URI used by `RedirectUri`; compare scheme, port, path, and slash. |
| Entra reports implicit grant is disabled | Enable access-token implicit grant in the app registration; also enable ID tokens when using `IncludeIdToken`. |
| Consent or invalid-scope error | Request valid delegated scopes for the intended resource and grant consent. |
| No token visible to a server callback | This is expected for fragment response mode. Capture the full URL in browser-side code or paste it into the companion parsing command. |

## Security notes

The state value is a CSRF/correlation control. Keep it per authorization attempt, unpredictable, and validate it before using tokens. Do not use a fixed state in production. Treat the redirect URL and its fragment as sensitive because they can contain bearer tokens; avoid browser history, referrer leakage, screenshots, logs, and copied terminal transcripts. Prefer authorization code + PKCE whenever the app supports it.

## Verbose diagnostics

Use `-Verbose` to see the tenant, client, redirect URI, scope, response type, and the authorization endpoint/query parameter names:

```powershell
New-EntraIDImplicitAuthorizationUrl -TenantId $tenantId -ClientId $clientId `
  -RedirectUri $redirectUri -Scope 'https://graph.microsoft.com/User.Read' -Verbose
```

Generated or supplied state and any nonce are masked by length. The complete authorization URL is returned as the command output but is not written to verbose logs, preventing state leakage.
