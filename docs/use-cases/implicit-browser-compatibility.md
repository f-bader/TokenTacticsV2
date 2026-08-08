# Support an existing implicit-flow browser application

Use this only when an existing Entra app cannot yet migrate to authorization code
flow with PKCE. Microsoft recommends authorization code + PKCE for new applications.

## Entra setup

1. Register the exact HTTPS redirect URI.
2. Enable Access tokens under Implicit grant and hybrid flows.
3. Grant the delegated permissions needed by the browser app.
4. Use a tenant-specific or organizations authority appropriate for the app.

## Generate the URL

    $request = New-EntraIDImplicitAuthorizationUrl -TenantId 'organizations' -ClientId $clientId -RedirectUri 'https://app.example/callback' -Scope 'https://graph.microsoft.com/User.Read'
    Start-Process $request.AuthorizationUrl

The command returns AuthorizationUrl and State. Preserve State in the browser flow;
do not put secrets or sensitive data in it.

## Parse the browser redirect

The browser returns tokens in the URL fragment, which is not sent to the web server.
Paste or otherwise pass the final redirect URL to:

    $token = ConvertFrom-EntraIDImplicitRedirect -RedirectUrl $finalUrl -ExpectedState $request.State

The result exposes AccessToken, IdToken when requested, TokenType, ExpiresIn, Scope,
State, Error, and ErrorDescription.

## Failure tests

- Change ExpectedState and verify rejection.
- Use an unregistered redirect URI.
- Disable implicit access tokens and verify Entra's unsupported-response error.
- Remove a delegated permission and verify the consent/error response.
- Ensure access tokens do not enter server logs, browser history, telemetry, or URLs
  sent to third parties.

See the [URL reference](../commands/New-EntraIDImplicitAuthorizationUrl.md) and
[redirect parser reference](../commands/ConvertFrom-EntraIDImplicitRedirect.md).
