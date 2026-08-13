```
  ______      __                 __             __  _                     ___ 
 /_  __/___  / /_____  ____     / /_____ ______/ /_(_)_________   _   __ |__ \
  / / / __ \/ //_/ _ \/ __ \   / __/ __ `/ ___/ __/ / ___/ ___/  | | / / __/ /
 / / / /_/ / ,< /  __/ / / /  / /_/ /_/ / /__/ /_/ / /__(__  )   | |/ / / __/ 
/_/  \____/_/|_|\___/_/ /_/   \__/\__,_/\___/\__/_/\___/____/    |___(_)____/     
```

# TokenTactics v2

This is an updated version of [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) originally written by Stephan Borosh [@rvrsh3ll](https://github.com/rvrsh3ll) & Bobby Cooke [@0xBoku](https://github.com/boku7).

## Microsoft Entra ID OAuth, Token, and Workload Authentication Toolkit

TokenTactics v2 is a PowerShell toolkit for authorized security research, red-team
engagements, identity testing, and defensive engineering with Microsoft Entra ID.
It helps obtain, exchange, refresh, inspect, and clear access and refresh tokens
across interactive, delegated, application, workload, and brokered authentication
flows.

Supported scenarios include device code and authorization code authentication,
passkey/FIDO2 sign-in, ESTSAUTH and SCCAUTH cookie exchange, refresh-token and
Continuous Access Evaluation (CAE) workflows, client credentials, on-behalf-of
(OBO), certificate and TPM-backed authentication, workload identity federation
(including GitHub Actions and Azure Arc), custom OIDC providers, and nested app
authentication. Tokens can be used with Microsoft Graph, Azure management,
SharePoint, OneDrive, Exchange, Teams, and other supported Microsoft cloud
workloads.

Use TokenTactics only against tenants, accounts, applications, and workloads for
which you have explicit authorization.

Scenario-based OAuth and workload guides are in
[docs](./docs/README.md); the individual command reference is in
[docs/commands](./docs/commands/README.md).

For more information about Microsoft Entra ID access tokens, see the Microsoft
documentation on [Microsoft identity platform access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).

There are example requests to Microsoft cloud endpoints in the `resources` folder,
as well as an example device-code authentication template.

You may also use these tokens with [AAD Internals](https://o365blog.com/aadinternals/).

## Installation and Usage

```powershell
Import-Module .\TokenTactics.psd1
Get-Help Get-EntraIDTokenFromDeviceCode
Invoke-RefreshToSubstrateToken -Domain "myclient.org"
```

## Testing

The test suite requires PowerShell 7 and Pester 5.7.1. It uses mocked HTTP responses and does not require Entra ID credentials or network access.

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
pwsh ./tests/Invoke-Tests.ps1
```

The same suite runs on Linux, macOS, and Windows for every pull request.

### Get refresh token using Device Code flow

```powershell
Get-EntraIDTokenFromDeviceCode -Client MSGraph
```

Once the user has logged in, the OAuth token response is saved in the `$response`
variable. Access the bearer token with `$response.access_token` or the refresh
token with `$response.refresh_token`.

### Authenticate an application with a TPM-backed certificate

> [!IMPORTANT]
> Creating TPM-backed certificates requires Windows, a provisioned TPM, and the Microsoft Platform Crypto Provider.

Create a non-exportable RSA certificate in your current user's personal store and export only its public certificate. The `.cer` file is DER encoded and can be uploaded under **App registrations > Certificates & secrets > Certificates**. Configure the application permissions required by the target resource and grant tenant admin consent before requesting a token.

```powershell
$certificate = New-TPMCertificate `
    -Subject 'CN=EntraID-TPM-Auth' `
    -PublicKeyPath 'C:\Temp\EntraID-TPM-Auth.cer'

$token = Get-EntraIDTokenFromCertificate `
    -TenantId 'contoso.onmicrosoft.com' `
    -ClientId '00000000-0000-0000-0000-000000000000' `
    -CertificateThumbprint $certificate.Thumbprint `
    -Scope 'https://graph.microsoft.com/.default'
```

`Get-EntraIDTokenFromCertificate` returns the OAuth token response and also saves it in `$response`. `New-TPMCertificate` defaults to `Cert:\CurrentUser\My`; use `-CertStoreLocation Cert:\LocalMachine\My` for a service account when the process has the necessary permissions. The TPM private key is deliberately non-exportable; only the public `.cer` file is written to disk.

#### DOD/Mil Device Code

```powershell
Get-EntraIDTokenFromDeviceCode -Client DODMSGraph
```

### Sign-in using a passkey

> [!IMPORTANT]
> This feature was introduced in v0.2.20 and requires PowerShell 7.0.

If you have created a passkey in a third party provider like KeePassXC, Bitwarden, 1Password, or similar you can export the private key material.

> [!CAUTION]
> Exporting your private key material is extremely dangerous. Make sure you understand the risk before you proceed.

The KeePassXC passkey file format is natively supported and you can point the cmdlet to the file directly. The initial sign-in procedure will only get the required ESTSAUTH cookie and you have to use `Get-EntraIDTokenFromESTSCookie` to exchange this cookie for a bearer token (access token, refresh token, and id token).

```powershell
# Retrieve the ESTSAUTH cookie value
Invoke-EntraIDPasskeyLogin -Verbose -KeyFilePath "C:\Users\Fabian\Microsoft.passkey"
# Exchange the ESTSAUTH cookie for bearer tokens
Get-EntraIDTokenFromESTSCookie -CookieValue $Global:ESTSAUTH
```

If you have an unsupported file format you can specify the required values manually and achieve the same goal.

```powershell
Invoke-EntraIDPasskeyLogin -Verbose -UserPrincipalName "myUserName@example.com" -UserHandle "XYZ" -CredentialId "9e9c8297-0cde-4726-8852-16c141e15bd3" -PrivateKey $PrivateKey
Get-EntraIDTokenFromESTSCookie -CookieValue $Global:ESTSAUTH
```

#### Split passkey flow (e.g. Windows Hello for Business)

The passkey sign-in is also available as separate cmdlets, which allows the assertion to be signed on a different machine than the one running the login flow — for example with a Windows Hello for Business credential (based on [ROADtools](https://github.com/dirkjanm/ROADtools) by Dirk-jan Mollema, MIT licensed).

```powershell
# 1. Retrieve structured FIDO2 flow state (also saves $global:Fido2FlowState and
#    the web session as $global:Fido2WebSession)
$flow = Get-EntraIDFido2Challenge -UserPrincipalName "user@contoso.com" -Client MSGraph

# 2. Create a signed assertion with the Windows Hello for Business key (Windows only)
#    The object ID is derived from the certificate's user SID; pass -UserId to override it.
#    The assertion is returned as a JSON string, e.g. for transfer via clipboard:
#    Get-WindowsHelloFidoAssertion -Challenge $flow.Challenge | Set-Clipboard
$assertion = Get-WindowsHelloFidoAssertion -Challenge $flow.Challenge -UserId "00000000-0000-0000-0000-000000000002"

# 3. Complete the sign-in. Returns an access token and refresh token by default.
Invoke-EntraIDPasskeyAssertionLogin -FlowState $flow -Assertion $assertion

# Alternatively, return the ESTSAUTH cookie value instead of tokens
Invoke-EntraIDPasskeyAssertionLogin -Assertion $assertion -OutputType ESTSAUTHCookie
```

The challenge cmdlet builds the authorization URL from the same client names used by the
refresh-token cmdlets, such as `MSGraph`, `Graph`, `MSTeams`, `AzureManagement`, `SharePoint`,
and `DeviceRegistration`. OAuth options include `-Tenant`, `-Authority`, `-RedirectUrl`,
`-Scope`, `-Resource`, `-UseV1Endpoint`, `-UseCAE`, `-UseCodeVerifier`, and `-CodeVerifier`.
When `-RedirectUrl` is omitted, the helper selects the preferred registered redirect URI for the
effective client ID using its maintained first-party client mapping; an explicit value overrides it.
Use `-AuthUrl` when a complete custom authorization URL is required. Unknown/custom client IDs
must provide `-RedirectUrl` because a generic native redirect may not be registered for that app.

If you need the FIDO2 user handle of a user (e.g. for the software-based passkey flow), you can calculate it from the tenant ID and the user's object ID:

```powershell
New-EntraIDUserHandle -TenantId "00000000-0000-0000-0000-000000000001" -UserId "00000000-0000-0000-0000-000000000002"
```

Use the returned `UserHandle` or `UserHandleBase64Url` property in an assertion. The legacy
`UserHandleBase64` property remains padded standard Base64 for compatibility.

### Get access tokens using the SCCAUTH cookie

If you have obtained an `sccauth` cookie from an authenticated session to `security.microsoft.com` (e.g., via Evilginx or browser DevTools), you can use it to retrieve Entra ID access tokens for a broad set of resources through the Microsoft Defender XDR portal.

```powershell
# Retrieve a Microsoft Graph token using the sccauth cookie
Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -ResourceName MicrosoftGraph

# Provide an XSRF token explicitly to skip the bootstrapping request
Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -XSRF "your_xsrf_value" -ResourceName Azure

# Use a custom resource URL
Get-EntraIDTokenFromSCCAUTHCookie -SCCAuth "your_sccauth_value" -Resource "https://management.core.windows.net/"
```

Supported `-ResourceName` values: `Azure`, `LogAnalytics`, `MATP`, `MCAS`, `MicrosoftGraph`, `MicrosoftOffice`, `Purview`, `PurviewACC`, `ThreatIntelligencePortal`.

### Get a Refresh Token from ESTSAuth* Cookie

```powershell
Get-EntraIDTokenFromESTSCookie -ESTSAuthCookie "0.AbcApTk..."
```

This module uses authorization code flow to obtain an access token and refresh token
using an ESTSAuth (or ESTSAuthPersistent) cookie. Use it only when you have obtained
the cookie from an authorized test session.

Be sure to use the right cookie! `ESTSAuthPersistent` is only useful when a CA policy actually grants a persistent session. Otherwise, you should use `ESTSAuth`. You can usually tell which one to use based on length, the longer cookie is the one you want to use :)

This feature was backported from the [pull request](https://github.com/rvrsh3ll/TokenTactics/pull/9/) by [rotarydrone](https://github.com/rotarydrone) in the original repo.

### Get a refresh token using the authorization code flow

One prominent example of this [OAuth 2.0 flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) is the Intune Company Portal, which can provide access to some resources under particular tenant and Conditional Access configurations.

This intel was first published by [@dirkjan](https://bsky.app/profile/dirkjanm.io/post/3ld4nbbhqd222) and then released at [Black Hat Europe](https://github.com/secureworks/pytune) to a wider audience by [@TEMP43487580](https://x.com/TEMP43487580/status/1866882057743282432)

JumpsecLabs published a [blog article](https://labs.jumpsec.com/tokensmith-bypassing-intune-compliant-device-conditional-access/) and a POC in form of [TokenSmith](https://github.com/JumpsecLabs/TokenSmith) shortly after.

Now the same capabilities are available in TokenTacticsV2.

`Get-EntraIDAuthorizationCode` creates a URL that you can use to authenticate.

`Get-EntraIDTokenFromAuthorizationCode` accepts either the full redirect URL or the
`AuthorizationCode` and `RedirectUrl` parameters to exchange the authorization code
for access and refresh tokens.

![How to use the new cmdlets](./images/EntraIDAuthorizationCodeFlow.gif)

### Get a nested app token using NAA / BroCi

`Get-EntraIDTokenFromNestedAppAuth` exchanges a broker application's refresh token for a token issued to a nested application. By default, the cmdlet uses the Azure Portal broker (`c44b4083-3bb0-49c1-b47d-974e53cbdf3c`) and the ADIbizaUX nested client (`74658136-14ec-4630-ad9b-26e160ff0fc6`) with Microsoft Graph scopes. Override the broker, nested client, scope, and redirect values as needed.

Supported broker presets: `AzurePortal`, `Teams`, `Microsoft365`, `EntraAdminCenter`, `IntuneAdminCenter`, `Defender`, `Purview`.

```powershell
Get-EntraIDTokenFromNestedAppAuth `
    -BrokerPreset Defender `
    -TenantId "e3686c4f-af27-4f22-b9de-062f05b93aac" `
    -RefreshToken $response.refresh_token `
    -AnchorMailbox "Oid:3135fd4e-140c-43c0-ad02-718913648fb9@e3686c4f-af27-4f22-b9de-062f05b93aac" `
    -UseCAE
```

If you omit `-RefreshToken`, the cmdlet falls back to `$response.refresh_token`. If you omit `-RedirectUri`, it is derived from `-BrokerClientId` and `-BrokerRedirectUri` using the brokered `brk-<brokerClientId>://<broker-host>` format. Explicit `-BrokerClientId`, `-BrokerRedirectUri`, and `-AuthorityHost` values override `-BrokerPreset`.

The `Teams` preset follows the newer `teams.cloud.microsoft` broker shape and automatically adds the `client_id` token-endpoint query parameter, `brk-multihub://m365.cloud.microsoft` redirect URI, and the MSAL browser telemetry fields seen in current Teams requests.

### Refresh to new access token

If you do not specify a refresh token the cmdlets will use `$response.refresh_token` as a default.

```powershell
Invoke-RefreshToOutlookToken -domain "myclient.org"

$OutlookToken.access_token
```

### Additional OAuth 2.0 and workload flows

#### Client secret and on-behalf-of

Get-EntraIDTokenFromClientSecret implements the application-only client credentials
grant. Supply either -ClientSecret or -ClientSecretSecureString; neither value is
written by the cmdlet.

    Get-EntraIDTokenFromClientSecret -TenantId 'contoso.onmicrosoft.com' -ClientId '00000000-0000-0000-0000-000000000000' -ClientSecret 'client-secret-value' -Scope 'https://graph.microsoft.com/.default'

Get-EntraIDTokenOnBehalfOf exchanges an incoming access token issued to the
middle-tier app for a downstream delegated token. The assertion must have the
middle-tier application as its audience.

    Get-EntraIDTokenOnBehalfOf -TenantId 'contoso.onmicrosoft.com' -ClientId '00000000-0000-0000-0000-000000000000' -ClientSecret 'client-secret-value' -UserAssertion $incomingAccessToken -Scope 'https://graph.microsoft.com/User.Read'

#### Federated credentials, GitHub Actions, and Azure Arc

Get-EntraIDTokenFromFederatedCredential exchanges an external OIDC JWT for an
application token. It accepts -FederatedToken, -FederatedTokenSecureString, or
-FederatedTokenPath. The Entra federated credential must exactly match the JWT
issuer, subject, and audience.

    Get-EntraIDTokenFromGitHubActions -TenantId $env:AZURE_TENANT_ID -ClientId $env:AZURE_CLIENT_ID -Scope 'https://management.azure.com/.default'

The GitHub workflow needs permissions: id-token: write. Configure the app
registration federated credential for the target repository/environment and the
api://AzureADTokenExchange audience.

Get-EntraIDTokenFromAzureArcManagedIdentity retrieves a resource token from the
local Azure Arc managed-identity endpoint. It runs only where IDENTITY_ENDPOINT is
present and completes the endpoint's local challenge-file protocol; it is not a
federated-credential exchange.

#### Implicit flow compatibility

Entra recommends authorization code flow with PKCE. When an existing registration
requires implicit access tokens, generate an authorization URL and then paste the
final browser redirect back into the parser:

    $request = New-EntraIDImplicitAuthorizationUrl -TenantId 'organizations' -ClientId '00000000-0000-0000-0000-000000000000' -RedirectUri 'https://app.example/callback' -Scope 'https://graph.microsoft.com/User.Read'
    Start-Process $request.AuthorizationUrl
    $token = ConvertFrom-EntraIDImplicitRedirect -RedirectUrl '<pasted-final-url>' -ExpectedState $request.State

Enable Access tokens under the application registration's Implicit grant and hybrid
flows before using this flow.

#### Custom federated credential provider

This workflow makes a local certificate the signer for a custom external OIDC
issuer. Only public discovery metadata and JWKS are hosted; the PFX/private key and
New-EntraIDFederatedClientAssertion remain on the assertion-issuing machine.
Hosting options are a Cloudflare named tunnel in front of the checked-in loopback
static host (infra/Start-TTFederatedIssuerStaticHost.ps1) or an Azure Storage
static website (infra/oidc-static-website.bicep).

    $certificate = New-EntraIDFederatedSigningCertificate -PfxPath $pfxPath -PfxPasswordSecureString $password -PublicCertificatePath $publicCertificatePath
    $metadata = New-EntraIDFederatedIssuerMetadata -Issuer $issuer -Subject $subject -OutputPath $metadataPath -PfxPath $pfxPath -PfxPasswordSecureString $password
    $assertion = New-EntraIDFederatedClientAssertion -Issuer $issuer -Subject $subject -PfxPath $pfxPath -PfxPasswordSecureString $password
    $token = Get-EntraIDTokenFromFederatedCredential -TenantId $tenantId -ClientId $clientId -FederatedToken $assertion -Scope $scope

The full step-by-step guide with hosting, publishing, verification, Entra
configuration, and key rotation is in
[docs/use-cases/custom-oidc-provider.md](./docs/use-cases/custom-oidc-provider.md).

### Connect to AzureAD using access token

```powershell
Connect-AzureAD -AadAccessToken $response.access_token -AccountId user@myclient.org
```

### Connect to MgGraph using access token

```powershell
Invoke-RefreshToMSGraphToken -Domain "myclient.org"
Connect-MgGraph -AccessToken $MSGraphToken.access_token -Scopes "User.Read.All","Group.ReadWrite.All"
```

### Clear tokens

This will remove any token variables.

```powershell
Clear-Token -Token All
```

### Continuous Access Evaluation

With [Continuous Access Evaluation (CAE)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation), Microsoft enables supported services to react to critical events and applicable Conditional Access policy changes during a token's lifetime. Microsoft currently documents these five critical events:

* User account is deleted or disabled
* Password for a user is changed or reset
* Multifactor authentication is enabled for the user
* Administrator explicitly revokes all refresh tokens for a user
* High user risk is detected by Microsoft Entra ID Protection

These are critical-event evaluations and do not depend on Conditional Access
policies. Microsoft notes that SharePoint Online doesn't support user-risk events.
Separately, CAE-capable services can evaluate supported Conditional Access policies,
including IP-based location changes; support varies by client and resource provider.

[Universal Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-universal-continuous-access-evaluation)
extends CAE through Global Secure Access. It applies the same Entra ID identity
signals to network access at the Global Secure Access edge, including for applications
that are not CAE-aware, and can require near-real-time reauthentication.

```powershell
Invoke-RefreshToMSGraphToken -Domain "myclient.org" -UseCAE
if ((Parse-JWTtoken $MSGraphToken.access_token).ValidForHours -gt 23) { "MSGraph token is CAE capable" }
```

### Use with AAD Internals

If you have AADInternals installed as well you can use the created access tokens.

```powershell
Invoke-RefreshToMSTeamsToken -UseCAE -Domain "myclient.org"
Set-AADIntTeamsStatusMessage -Message "My cool status message" -AccessToken $MSTeamsToken.access_token -Verbose
```

### Commands

```powershell
Get-Command -Module TokenTactics
```

Only supported user-facing commands are exported; parsing, PKCE, generic refresh, and FIDO cryptographic helpers remain private implementation details.

## Authors and contributors
- [@rvrsh3ll](https://github.com/rvrsh3ll) Author of TokenTactics (original)
- [@0xBoku](https://github.com/boku7) co-author of TokenTactics (original) and researcher.
- [@f-bader](https://github.com/f-bader) updated TokenTactics to support V2 endpoint and additional features like CAE. Maintainer of TokenTacticsV2
- [@Pri3st](https://github.com/Pri3st) added functions to fetch Storage and Key Vault access tokens and a custom user agent

TokenTactics' methods are highly influenced by the research of Dr. Nestori Syynimaa at https://o365blog.com/.

## Changelog

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
* Support for [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity-platform/continuous-access-evaluation) using the new `-UseCAE` switch
* Made `ClientId` a parameter
* Changed `client_id` for MSTeams
* Added support for OneDrive and SharePoint
* Added `IssuedAt`, `NotBefore`, `ExpirationDate` and `ValidForHours` in `ConvertFrom-JWTtoken` output in human readable format
* Passkey sign-in support
* Refactored the codebase to for easier maintenance
