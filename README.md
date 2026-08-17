```
  ______      __                 __             __  _                     ___ 
 /_  __/___  / /_____  ____     / /_____ ______/ /_(_)_________   _   __ |__ \
  / / / __ \/ //_/ _ \/ __ \   / __/ __ `/ ___/ __/ / ___/ ___/  | | / / __/ /
 / / / /_/ / ,< /  __/ / / /  / /_/ /_/ / /__/ /_/ / /__(__  )   | |/ / / __/ 
/_/  \____/_/|_|\___/_/ /_/   \__/\__,_/\___/\__/_/\___/____/    |___(_)____/     
```

# TokenTactics v2

TokenTactics v2 is a PowerShell toolkit for authorized Microsoft Entra ID security
research, red-team validation, and defensive engineering. It obtains, exchanges,
refreshes, inspects, and clears tokens across interactive, delegated, application,
workload, passkey, cookie, and brokered authentication flows.

The canonical documentation covers the complete exported command surface and
scenario-based procedures:

- [Documentation and scenario guides](./docs/README.md)
- [Exported command reference](./docs/commands/README.md)
- [Custom OIDC provider guide](./docs/use-cases/custom-oidc-provider.md)
- [Continuous Access Evaluation guide](./docs/use-cases/continuous-access-evaluation.md)

Use the toolkit only against tenants, accounts, applications, workloads, and
sessions for which you have explicit authorization. Treat tokens, cookies,
passkey key material, certificates, and client credentials as secrets.

## Installation and quick start

```powershell
Import-Module ./TokenTactics.psd1
Get-Help Get-EntraIDTokenFromDeviceCode
Get-EntraIDTokenFromDeviceCode -Client MSGraph
```

After the authorized user completes sign-in, the OAuth response is available in
`$response`:

```powershell
$response.access_token
$response.refresh_token
```

For an overview of the supported flows, start with the
[interactive authentication guide](./docs/use-cases/interactive-user-authentication.md).

## Testing

The test suite requires PowerShell 7 and Pester 5.7.1. It uses mocked HTTP
responses and does not require Entra ID credentials or network access.

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
pwsh ./tests/Invoke-Tests.ps1
```

The suite runs on Linux, macOS, and Windows for every pull request.

## Project history

TokenTactics v2 is an updated version of [TokenTactics](https://github.com/rvrsh3ll/TokenTactics),
originally written by Stephan Borosh [@rvrsh3ll](https://github.com/rvrsh3ll) and
Bobby Cooke [@0xBoku](https://github.com/boku7). Current work includes Microsoft
Entra ID OAuth v2 flows, CAE, certificates and TPM-backed authentication, passkeys,
FIDO2 split flows, workload identity federation, nested app authentication, and
custom OIDC tooling.

## Authors and contributors

- [@rvrsh3ll](https://github.com/rvrsh3ll) — original TokenTactics author
- [@0xBoku](https://github.com/boku7) — original co-author and researcher
- [@f-bader](https://github.com/f-bader) — TokenTacticsV2 maintainer
- [@Pri3st](https://github.com/Pri3st) — Storage, Key Vault, and user-agent contributions

TokenTactics' methods are influenced by the research of Dr. Nestori Syynimaa at
[o365blog.com](https://o365blog.com/).

## Changelog

### 0.6.0 (2026-08-16)

* Centralize Entra first-party OAuth client IDs, scopes, authorities, endpoint versions, and redirect URIs in a shared registry.
* Preserve required legacy clients and redirect URIs while routing device-code, authorization-code, cookie, passkey, and refresh flows through the registry.
* Fix v1 device-code polling, native/URN redirect handling, passkey completion edge cases, and refresh-token verbose logging.
* Add regression coverage for the OAuth registry, native redirects, device-code contracts, passkey flows, and refresh commandlets.

### 0.5.0 (2026-08-13)

* Add OAuth 2.0 client-credentials, on-behalf-of, and implicit-flow compatibility cmdlets, including secure-string credential support and state validation.
* Add workload identity federation exchanges for external OIDC tokens, GitHub Actions, and Azure Arc managed identities.
* Add certificate-backed application and OBO authentication with Windows certificate-store and portable PFX support, including OpenSSL fallback on macOS and Linux.
* Add custom OIDC issuer tooling for signing certificates, discovery/JWKS metadata, client assertions, loopback hosting, and Azure Storage static website deployment.

### 0.4.0 (2026-08-12)

* Add `Get-EntraIDFido2Challenge` to retrieve a FIDO2 sign-in challenge and save the web session for the split passkey flow.
* Add `Get-WindowsHelloFidoAssertion` to create a signed WebAuthn assertion with a Windows Hello for Business key. Based on `fido_assertion.ps1` by Dirk-jan Mollema ([ROADtools](https://github.com/dirkjanm/ROADtools)), released under the MIT license.
* Add `New-EntraIDUserHandle` to calculate the FIDO2 user handle from a tenant ID and user object ID.
* Add `Invoke-EntraIDPasskeyAssertionLogin` to complete the passkey sign-in from a signed assertion, returning tokens by default or the ESTSAUTH cookie via `-OutputType ESTSAUTHCookie`.

### 0.3.3 (2026-08-05)

* Add `New-TPMCertificate` for creating non-exportable, Windows TPM-backed RSA certificates and optionally exporting their public DER certificate.
* Add `Get-EntraIDTokenFromCertificate` to request Entra ID application tokens through OAuth 2.0 client credentials with an RS256 certificate assertion.

### 0.3.2 (2026-07-26)

* Split the former `TokenHandler` implementation into grouped module files and split the matching test file into dedicated test files.
* Rename the device code cmdlet to `Get-EntraIDTokenFromDeviceCode` and keep `Get-EntraIDToken` as a compatibility alias.
* Add `TenantId` as an alias for the `Domain` parameter across the refresh-token cmdlets and their shared helper.

### 0.3.1 (2026-07-26)

* Add `Get-EntraIDTokenFromNestedAppAuth` to exchange broker refresh tokens for nested app tokens using NAA / BroCi.
* Add broker presets for Azure Portal, Teams, Microsoft 365, Entra admin center, Intune admin center, Defender, and Purview, including the newer `teams.cloud.microsoft` broker flow.
* Add deterministic Pester coverage for the new Nested App Authentication request contracts and export surface.

### 0.3.0 (2026-07-13)

* Add a pinned Pester 5 test runner, cross-platform GitHub Actions checks, test reports, and an enforced coverage baseline.
* Add deterministic mocked coverage for device code, cookie, authorization code, SCCAUTH, refresh-token, and passkey flows.
* Fix token cleanup, URL decoding, UTC JWT timestamps, PEM validation, Yammer scope, CAE cookie support, PurviewACC tenant headers, and passkey assertion construction.
* Export only supported user-facing commands and compatibility aliases. Implementation helpers previously exposed by the wildcard export are now private; scripts should use the corresponding public commands instead.

### 0.2.22 (2026-04-03)

* Add `Get-EntraIDTokenFromSCCAUTHCookie` to retrieve Entra ID access tokens for various resources (Azure, MicrosoftGraph, MATP, MCAS, Purview, etc.) using an `sccauth` cookie from `security.microsoft.com`. Optionally accepts an `XSRF` token; if omitted, bootstraps automatically. Supports an optional `TenantId` parameter for header injection and PurviewACC resource construction.

### 0.2.20 (2026-01-01)

* Renamed all `Get-Azure` cmdlets to `Get-EntraID`
* Add aliases for backwards compatibility
* Add improved error handling for ConvergedSignIn interrupts
* Add `Invoke-EntraIDPasskeyLogin` to automate Passkey sign-in flows. This will save the ESTSAUTH cookie and websession as global variables for reuse in other cmdlets like `Get-EntraIDTokenFromESTSCookie`
* Add proxy support for `Invoke-EntraIDPasskeyLogin`, `Get-EntraIDTokenFromCookie`, `Get-EntraIDTokenFromRefreshTokenCredentialCookie` and `Get-EntraIDTokenFromESTSCookie`

### 0.2.14 (2025-09-11)

* Add parameter `-Username` to prefill the **login_hint** parameter in cmdlet `Get-AzureAuthorizationCode`
* Add parameter `-CopyToClipboard` in cmdlet `Get-AzureAuthorizationCode`

### 0.2.13 (2025-07-29)

* Fix for Custom User Agent parameter

### 0.2.12 (2025-06-22)

* Add awareness for current runspace and minimize output if run as PSTask (e.g. if run in `Foreach-Object -parallel`)

### 0.2.11 (2025-06-08)

* Add the ability to freely define any UserAgent using the new `-CustomUserAgent` property. Thanks to [Pri3st](https://github.com/Pri3st)

### 0.2.10 (2025-02-25)

* Bugfix: Wrong type initialization

### 0.2.9 (2025-02-17)

* Add `ResourceTenant` for `Get-EntraIDToken` to support B2B device code phishing
* Switch out Azure Management client id
* Add `UseCodeVerifier` to support Proof Key for Code Exchange (PKCE)
* Add `UseV1Endpoint` to some functions to support a broader variety of endpoint tests

### 0.2.8 (2025-01-18)

* Add `Get-AzureTokenFromRefreshTokenCredentialCookie` ("x-ms-RefreshTokenCredential") and add modularized `Get-AzureTokenFromCookie`
* Add parameter to choose cookie type (ESTSAuth, ESTSAUTHPERSISTENT) to `Get-AzureTokenFromESTSCookie`
* Add sample output for `Get-AzureTokenFromAuthorizationCode` to `Get-AzureAuthorizationCode` output
* Improved output and more verbose error handling

### 0.2.7 (2025-01-08)

* Expand `Get-AzureTokenFromESTSCookie` to support the **appverify** endpoint
* Improve cookie management of `Get-AzureTokenFromESTSCookie`

### 0.2.6 (2025-01-04)

* Fix bug custom scopes in `Get-AzureAuthorizationCode` and `Get-AzureTokenFromAuthorizationCode`
* Change default redirect Uri for `Get-AzureAuthorizationCode`

### 0.2.5 (2025-01-04)

* Added new cmdlets `Get-AzureAuthorizationCode` and `Get-AzureTokenFromAuthorizationCode` \
  Those cmdlets are heavily inspired by [TokenSmith](https://github.com/JumpsecLabs/TokenSmith) maintained by [@gladstomych](https://github.com/gladstomych)
* Added new cmdlet `Invoke-RefreshToDeviceRegistrationToken` which is a TokenTactics version of the [AADInternals](https://github.com/Gerenios/AADInternals) cmdlet [`Get-AccessTokenForAADJoin`](https://github.com/Gerenios/AADInternals/blob/b23a7845f6dc5ea8c57b10351421a4d00466cd90/AccessToken.ps1#L877)
* Added v1 endpoint support for `Invoke-RefreshToToken` with the `UseV1Endpoint`. This was required to add `Invoke-RefreshToDeviceRegistrationToken`
* Added pipeline support for `ConvertFrom-JWTtoken`
* Add default values to `Get-ForgedUserAgent`

### 0.2.1 (2023-07-21)

* Support for Linux as a device platform
* Support for OS/2 as a device platform :grin:

### 0.2.2 (2023-07-22)

* Backported [Yammer token support](https://github.com/rvrsh3ll/TokenTactics/commit/9b364e45e39c70cc3d0a0c5ca85d36e395df8930)
* Backported [switch to allowed PowerShell verbs](https://github.com/rvrsh3ll/TokenTactics/commit/1e46bf26bcc799d4796b621e7f778fd0a24806ff), added alias for backward compatibility

### 0.2.3 (2023-07-23)

* Backported [pull request](https://github.com/rvrsh3ll/TokenTactics/pull/9/) by [rotarydrone](https://github.com/rotarydrone) to convert ESTSAuth to access token

## New Features in v2

* Switched to `v2.0` of the Azure AD OAuth2 endpoint
* Support for [continuous access evaluation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation) using the new `-UseCAE` switch
* Made `ClientId` a parameter
* Changed `client_id` for MSTeams
* Added support for OneDrive and SharePoint
* Added `IssuedAt`, `NotBefore`, `ExpirationDate` and `ValidForHours` in `ConvertFrom-JWTtoken` output in human readable format
* Passkey sign-in support
* Refactored the codebase to for easier maintenance
