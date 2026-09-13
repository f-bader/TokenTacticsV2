# Changelog

## Historical v2 highlights

- Move primary user-authentication flows to the Microsoft identity platform OAuth 2.0 v2 endpoint and add optional [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation) capability requests.
- Make client IDs configurable and update the Microsoft Teams client registration.
- Add OneDrive and SharePoint workload support.
- Add human-readable `IssuedAt`, `NotBefore`, `ExpirationDate`, and `ValidForHours` fields to decoded JWT output.

## 0.6.0 (2026-08-16)

- Centralize Entra first-party OAuth client IDs, scopes, authorities, endpoint versions, and redirect URIs in a shared registry.
- Preserve required legacy clients and redirect URIs while routing device-code, authorization-code, cookie, passkey, and refresh flows through the registry.
- Fix v1 device-code polling, native/URN redirect handling, passkey completion edge cases, and refresh-token verbose logging.
- Add regression coverage for the OAuth registry, native redirects, device-code contracts, passkey flows, and refresh cmdlets.

## 0.5.0 (2026-08-13)

- Add OAuth 2.0 client-credentials, on-behalf-of, and implicit-flow compatibility cmdlets, including secure-string credential support and state validation.
- Add workload identity federation exchanges for external OIDC tokens, GitHub Actions, and Azure Arc managed identities.
- Add certificate-backed application and OBO authentication with Windows certificate-store and portable PFX support, including OpenSSL fallback on macOS and Linux.
- Add custom OIDC issuer tooling for signing certificates, discovery/JWKS metadata, client assertions, loopback hosting, and Azure Storage static website deployment.

## 0.4.0 (2026-08-12)

- Add `Get-EntraIDFido2Challenge` to retrieve a FIDO2 sign-in challenge and save the web session for the split passkey flow.
- Add `Get-WindowsHelloFidoAssertion` to create a signed WebAuthn assertion with a Windows Hello for Business key. Based on `fido_assertion.ps1` by Dirk-jan Mollema ([ROADtools](https://github.com/dirkjanm/ROADtools)), released under the MIT license.
- Add `New-EntraIDUserHandle` to calculate the FIDO2 user handle from a tenant ID and user object ID.
- Add `Invoke-EntraIDPasskeyAssertionLogin` to complete the passkey sign-in from a signed assertion, returning tokens by default or the ESTSAUTH cookie via `-OutputType ESTSAUTHCookie`.

## 0.3.3 (2026-08-05)

- Add `New-TPMCertificate` for creating non-exportable, Windows TPM-backed RSA certificates and optionally exporting their public DER certificate.
- Add `Get-EntraIDTokenFromCertificate` to request Entra ID application tokens through OAuth 2.0 client credentials with an RS256 certificate assertion.

## 0.3.2 (2026-07-26)

- Split the former `TokenHandler` implementation into grouped module files and split the matching test file into dedicated test files.
- Rename the device code cmdlet to `Get-EntraIDTokenFromDeviceCode` and keep `Get-EntraIDToken` as a compatibility alias.
- Add `TenantId` as an alias for the `Domain` parameter across the refresh-token cmdlets and their shared helper.

## 0.3.1 (2026-07-26)

- Add `Get-EntraIDTokenFromNestedAppAuth` to exchange broker refresh tokens for nested app tokens using NAA/BroCi.
- Add broker presets for Azure Portal, Teams, Microsoft 365, Entra admin center, Intune admin center, Defender, and Purview, including the newer `teams.cloud.microsoft` broker flow.
- Add deterministic Pester coverage for the new Nested App Authentication request contracts and export surface.

## 0.3.0 (2026-07-13)

- Add a pinned Pester 5 test runner, cross-platform GitHub Actions checks, test reports, and an enforced coverage baseline.
- Add deterministic mocked coverage for device code, cookie, authorization code, SCCAUTH, refresh-token, and passkey flows.
- Fix token cleanup, URL decoding, UTC JWT timestamps, PEM validation, Yammer scope, CAE cookie support, PurviewACC tenant headers, and passkey assertion construction.
- Export only supported user-facing commands and compatibility aliases. Implementation helpers previously exposed by the wildcard export are now private; scripts should use the corresponding public commands instead.

## 0.2.22 (2026-04-03)

- Add `Get-EntraIDTokenFromSCCAUTHCookie` to retrieve Entra ID access tokens for resources including Azure, Microsoft Graph, MATP, MCAS, and Purview using an `sccauth` cookie from `security.microsoft.com`.
- Add optional XSRF input and automatic bootstrap, plus tenant header injection and PurviewACC resource construction.

## 0.2.20 (2026-01-01)

- Rename all `Get-Azure` cmdlets to `Get-EntraID` and retain compatibility aliases.
- Improve error handling for ConvergedSignIn interrupts.
- Add `Invoke-EntraIDPasskeyLogin`, which saves the ESTSAUTH cookie and web session for reuse by commands such as `Get-EntraIDTokenFromESTSCookie`.
- Add proxy support for passkey and cookie authentication commands.

## 0.2.14 (2025-09-11)

- Add `-Username` to prefill `login_hint` and `-CopyToClipboard` to the authorization-code URL command.

## 0.2.13 (2025-07-29)

- Fix custom user-agent handling.

## 0.2.12 (2025-06-22)

- Add runspace awareness and minimize output when running as a PowerShell task, such as `ForEach-Object -Parallel`.

## 0.2.11 (2025-06-08)

- Add `-CustomUserAgent` for caller-defined user-agent values. Thanks to [Pri3st](https://github.com/Pri3st).

## 0.2.10 (2025-02-25)

- Fix an incorrect type initialization.

## 0.2.9 (2025-02-17)

- Add `ResourceTenant` to device-code authentication for B2B scenarios.
- Update the Azure Management client ID.
- Add PKCE support through `UseCodeVerifier`.
- Add v1 endpoint support to selected commands.

## 0.2.8 (2025-01-18)

- Add refresh-token-credential cookie authentication and modular cookie exchange.
- Add ESTSAUTH/ESTSAUTHPERSISTENT selection to the ESTS cookie command.
- Improve authorization-code sample output, cookie management, and error handling.

## 0.2.7 (2025-01-08)

- Expand ESTS cookie exchange to support the `appverify` endpoint and improve cookie management.

## 0.2.6 (2025-01-04)

- Fix custom scopes in authorization-code URL and token exchange commands.
- Change the default redirect URI for authorization-code URL generation.

## 0.2.5 (2025-01-04)

- Add authorization-code URL and token exchange commands, inspired by [TokenSmith](https://github.com/JumpsecLabs/TokenSmith).
- Add the Device Registration refresh wrapper based on the AADInternals access-token flow.
- Add v1 endpoint support to refresh-token exchange.
- Add pipeline support to `ConvertFrom-JWTtoken` and defaults to `Get-ForgedUserAgent`.

## 0.2.3 (2023-07-23)

- Backport [pull request 9](https://github.com/rvrsh3ll/TokenTactics/pull/9/) by [rotarydrone](https://github.com/rotarydrone) to convert ESTSAUTH cookies to access tokens.

## 0.2.2 (2023-07-22)

- Backport Yammer token support and the switch to approved PowerShell verbs, retaining compatibility aliases.

## 0.2.1 (2023-07-21)

- Add Linux and OS/2 device-platform profiles.
