# Interactive, cookie, and brokered authentication commands

These commands obtain or exchange tokens for an authorized user session. They are
grouped because several wrappers delegate to the same OAuth authorization-code
contract.

## Get-EntraIDTokenFromDeviceCode

Requests a device code, displays the verification instructions, polls Entra ID, and
saves the resulting token response in `$response`.

| Parameter | Purpose |
| --- | --- |
| `-Client` | Preset resource: `Yammer`, `Outlook`, `MSTeams`, `Graph`, `AzureCoreManagement`, `AzureManagement`, `MSGraph`, `DODMSGraph`, `Substrate`, `SharePoint`, or `OneDrive`. |
| `-ClientID` | Override the preset public-client ID. |
| `-Scope` | Scope for `-Client Custom`. |
| `-ResourceTenant` | Tenant authority segment; `-Domain` is a compatibility alias. |
| `-SharePointTenantName` | SharePoint host name; required for the SharePoint preset. |
| `-SharePointUseAdmin` | Select the SharePoint admin host. |
| `-UseCAE` | Request the `cp1` client capability. |
| `-Device`, `-Browser`, `-CustomUserAgent` | Select request metadata. |

```powershell
Get-EntraIDTokenFromDeviceCode -Client MSGraph
Get-EntraIDTokenFromDeviceCode -Client Custom -ClientID $clientId -Scope 'api://app/.default offline_access'
```

## Get-EntraIDAuthorizationCode

Builds and prints an authorization URL plus the follow-up exchange command. It does
not itself exchange the code.

| Parameter | Purpose |
| --- | --- |
| `-Client`, `-ClientID`, `-Scope` | Select the application and resource contract. |
| `-RedirectUrl` | Exact registered redirect URI. |
| `-AuthorizationCodeState` | State value printed into the URL. |
| `-Username` | Optional `login_hint`. |
| `-UseCodeVerifier` | Generate a PKCE verifier and print it in the exchange command. |
| `-UseV1Endpoint`, `-Resource` | Use the legacy resource-based authorization contract. |
| `-OpenInBrowser` | Open the URL through the local PowerShell host. |
| `-CopyToClipboard` | Copy the URL when clipboard support is available. |

```powershell
Get-EntraIDAuthorizationCode `
    -Client MSGraph `
    -RedirectUrl 'https://app.example/callback' `
    -UseCodeVerifier
```

## Get-EntraIDTokenFromAuthorizationCode

Exchanges either `-RequestURL` or an explicit `-AuthorizationCode` and
`-RedirectUrl` for tokens. The response is saved in `$response`.

```powershell
Get-EntraIDTokenFromAuthorizationCode `
    -RequestURL $finalRedirectUrl `
    -Client MSGraph

Get-EntraIDTokenFromAuthorizationCode `
    -AuthorizationCode $code `
    -RedirectUrl 'https://app.example/callback' `
    -Client Custom `
    -ClientID $clientId `
    -Scope 'api://app/.default offline_access'
```

Use `-CodeVerifier` to complete a PKCE exchange and `-UseV1Endpoint -Resource` for
a legacy resource request. `-Browser`, `-Device`, and `-CustomUserAgent` affect
request metadata only.

## Get-EntraIDTokenFromCookie

Uses a supplied cookie to obtain an authorization code and exchange it for tokens.
`-CookieType`, `-CookieValue`, `-ClientID`, `-Scope`, and `-RedirectUrl` are the
core request inputs. `-UseCodeVerifier`, `-CodeVerifier`, `-UseV1Endpoint`,
`-Resource`, `-UseCAE`, and `-Proxy` are supported for the corresponding endpoint.

```powershell
Get-EntraIDTokenFromCookie `
    -CookieType ESTSAUTH `
    -CookieValue $cookieValue `
    -ClientID $clientId `
    -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient'
```

## Get-EntraIDTokenFromESTSCookie

Convenience wrapper for `Get-EntraIDTokenFromCookie` with `-ESTSCookieType`
`ESTSAUTH` or `ESTSAUTHPERSISTENT`. `-ESTSAuthCookie` is a compatibility alias for
`-CookieValue`. The client presets are `MSTeams`, `MSEdge`, `AzurePowershell`,
`AzureManagement`, `DeviceComplianceBypass`, and `Custom`.

```powershell
Get-EntraIDTokenFromESTSCookie `
    -ESTSAuthCookie $estsAuth `
    -ESTSCookieType ESTSAUTH `
    -Client MSTeams
```

## Get-EntraIDTokenFromRefreshTokenCredentialCookie

Convenience wrapper for the `x-ms-RefreshTokenCredential` cookie. Use
`-RefreshTokenCredential`, a client preset or explicit `-ClientID`, and the exact
`-RedirectUrl` required by the authorized registration.

```powershell
Get-EntraIDTokenFromRefreshTokenCredentialCookie `
    -RefreshTokenCredential $credentialCookie `
    -Client MSTeams
```

## Get-EntraIDTokenFromSCCAUTHCookie

Uses an `sccauth` cookie from an authorized Microsoft Defender XDR session to obtain
a resource token. The automatic parameter set accepts `-ResourceName`; the manual
set accepts `-Resource` and optional `-ServiceType`. `-XSRF` skips the bootstrap
request when a current XSRF token is already available. `-TenantId` adds tenant
headers and supports PurviewACC tenant construction.

```powershell
Get-EntraIDTokenFromSCCAUTHCookie `
    -SCCAuth $sccAuth `
    -ResourceName MicrosoftGraph
```

## Get-EntraIDTokenFromNestedAppAuth

Exchanges a broker refresh token for a nested application token. Use
`-BrokerPreset` or explicit broker values. Presets are `AzurePortal`, `Teams`,
`Microsoft365`, `EntraAdminCenter`, `IntuneAdminCenter`, `Defender`, and `Purview`.

```powershell
Get-EntraIDTokenFromNestedAppAuth `
    -BrokerPreset AzurePortal `
    -TenantId $tenantId `
    -RefreshToken $response.refresh_token `
    -UseCAE
```

Important parameters include `-ClientId`, `-Scope`, `-RedirectUri`,
`-BrokerClientId`, `-BrokerRedirectUri`, `-AuthorityHost`, `-Claims`,
`-AnchorMailbox`, `-IncludeClientIdInQuery`, and the MSAL telemetry fields. If
`-RefreshToken` is omitted, `$response.refresh_token` is used. If `-RedirectUri`
is omitted, it is derived from the broker values.

See the [interactive authentication guide](../use-cases/interactive-user-authentication.md),
[cookie guide](../use-cases/cookie-session-exchange.md), and
[NAA guide](../use-cases/nested-app-authentication.md).
