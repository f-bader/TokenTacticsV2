# ConvertFrom-EntraIDImplicitRedirect

## Synopsis

Parses the fragment returned by an Entra implicit-flow redirect and verifies its state value before returning access-token, ID-token, scope, expiry, and authorization-error fields.

## Syntax

```powershell
ConvertFrom-EntraIDImplicitRedirect -RedirectUrl <string> -ExpectedState <string>
```

## Prerequisites

Use this after `New-EntraIDImplicitAuthorizationUrl` and an interactive browser sign-in. Preserve the corresponding `State` value from the authorization URL command and provide it as `ExpectedState`.

The input must be the **complete final redirect URL**, including the portion after `#`. Do not supply only the query string or the token itself. The response is normally placed in the URI fragment because the authorization URL requests `response_mode=fragment`.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `RedirectUrl` | Yes | Complete browser redirect URL containing an implicit response fragment. |
| `ExpectedState` | Yes | Exact state generated or chosen for the matching authorization request. Comparison is case-sensitive. |

## Examples

Parse a successful redirect:

```powershell
$request = New-EntraIDImplicitAuthorizationUrl `
  -TenantId $tenantId -ClientId $clientId `
  -RedirectUri 'https://app.example/callback' `
  -Scope 'https://graph.microsoft.com/User.Read'

# After browsing $request.AuthorizationUrl, paste the complete resulting URL.
$redirectUrl = Read-Host 'Final redirect URL'
$result = ConvertFrom-EntraIDImplicitRedirect `
  -RedirectUrl $redirectUrl -ExpectedState $request.State

if ($result.Error) {
    throw "$($result.Error): $($result.ErrorDescription)"
}

$result.AccessToken
```

Parse an authorization denial without treating it as a token:

```powershell
$result = ConvertFrom-EntraIDImplicitRedirect `
  -RedirectUrl 'https://app.example/callback#error=access_denied&error_description=The%20user%20cancelled&state=abc123' `
  -ExpectedState 'abc123'

$result.Error
$result.ErrorDescription
```

## Output and behavior

The command URL-decodes fragment fields and returns a custom object:

| Property | Description |
| --- | --- |
| `AccessToken` | Returned bearer token, or null/empty on an authorization error. |
| `IdToken` | Returned ID token when the request included it. |
| `TokenType` | Normally `Bearer`. |
| `ExpiresIn` | Lifetime in seconds as returned by Entra. |
| `Scope` | Granted delegated scopes. |
| `State` | Returned state after successful validation. |
| `Error` | OAuth authorization error, if Entra returned one. |
| `ErrorDescription` | Human-readable error detail, if returned. |

If the fragment is missing, the command throws. If the returned `state` is not exactly equal to `ExpectedState`, it throws and returns no result. A matching state does not turn an OAuth error into a success: callers must check `Error` before using `AccessToken`.

The command parses the redirect; it does not validate JWT signatures, inspect token claims, refresh tokens, call Entra, or store output.

## Errors and troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| `redirect URL does not contain an implicit-flow response fragment` | Paste the final URI including `#...`. Server-side callbacks often omit it because browsers do not send fragments in HTTP requests. |
| `state value did not match` | Do not use the redirect. Use the exact state paired with this browser request; a mismatch can indicate a stale request, a copy/paste error, or a CSRF attack. |
| `Error` is `access_denied` | The user cancelled, consent was denied, or policy blocked access. Inspect `ErrorDescription` and Entra sign-in logs. |
| `Error` is `invalid_request`/`invalid_scope` | Check the associated authorization URL, redirect URI registration, app settings, and delegated permissions. |

## Security notes

`RedirectUrl`, `AccessToken`, and `IdToken` can be credentials. Do not print, persist, or send them to logs, PowerShell history, transcripts, browser history, issue trackers, or chat. State validation is mandatory for every authorization attempt; this command deliberately uses an exact case-sensitive comparison. Because implicit flow exposes tokens to the user agent, migrate to authorization code + PKCE when possible.

## Verbose diagnostics

Add `-Verbose` to see the redirect host/path, fragment size, parsed parameter names, state-validation result, and safe output metadata:

```powershell
ConvertFrom-EntraIDImplicitRedirect -RedirectUrl $browserUrl `
  -ExpectedState $request.State -Verbose
```

The redirect fragment, state, access token, and ID token values are not emitted. They appear only as redacted lengths; errors and non-sensitive fields remain visible.
