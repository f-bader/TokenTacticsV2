# Get-EntraIDTokenOnBehalfOf

## Synopsis

Exchanges a user access token for a downstream API token using the OAuth 2.0 on-behalf-of (OBO) grant. The calling service authenticates with either its client secret or an RSA certificate.

## Syntax

```powershell
Get-EntraIDTokenOnBehalfOf -TenantId <string> -ClientId <string> `
  -UserAssertion <string> -Scope <string> -ClientSecret <string>

Get-EntraIDTokenOnBehalfOf -TenantId <string> -ClientId <string> `
  -UserAssertion <string> -Scope <string> -ClientSecretSecureString <securestring>

Get-EntraIDTokenOnBehalfOf -TenantId <string> -ClientId <string> `
  -UserAssertion <string> -Scope <string> -CertificateThumbprint <string> `
  [-CertStoreLocation <Cert:\\CurrentUser\\My|Cert:\\LocalMachine\\My>]

Get-EntraIDTokenOnBehalfOf -TenantId <string> -ClientId <string> `
  -UserAssertion <string> -Scope <string> -PfxPath <string> `
  [-PfxPassword <string>|-PfxPasswordSecureString <securestring>]
```

## Prerequisites and Entra setup

OBO is for a middle-tier API acting for a user: client application -> middle-tier API -> downstream API. It is not an app-only flow.

1. Register the middle-tier application and expose an API scope that the upstream client can request.
2. Configure the downstream API's **delegated** permissions on the middle-tier registration and grant consent as appropriate.
3. The incoming `UserAssertion` must be an Entra access token whose `aud` claim is the middle-tier `ClientId`; an ID token, token intended for another API, or opaque/non-JWT token is not valid.
4. Configure one confidential-client credential on the middle tier: a client secret, Windows certificate-store certificate, or PFX containing an accessible RSA private key. Upload the certificate's public key to the app registration when using certificate authentication.

On Windows, certificate-thumbprint lookup uses `Cert:\CurrentUser\My` by default or `Cert:\LocalMachine\My`. On macOS/Linux, use `PfxPath`; the module uses native .NET loading where supported and can fall back to OpenSSL.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `TenantId` | Yes | Entra tenant used for the token endpoint. |
| `ClientId` | Yes | Application/client ID of the middle-tier API. |
| `UserAssertion` | Yes | Incoming user access token for the middle tier. |
| `Scope` | Yes | Space-delimited delegated scopes for the downstream API, such as `https://graph.microsoft.com/User.Read`. OBO does not require `/.default`. |
| `ClientSecret` / `ClientSecretSecureString` | One auth option | Middle-tier secret, plaintext or `SecureString`. |
| `CertificateThumbprint` | One auth option | Windows certificate-store thumbprint for an RSA certificate with private key. |
| `CertStoreLocation` | No | Store used with `CertificateThumbprint`; defaults to `Cert:\CurrentUser\My`. |
| `PfxPath` | One auth option | Path to a PFX with an accessible RSA private key. |
| `PfxPassword` / `PfxPasswordSecureString` | Conditional | Password for the PFX. Plaintext and `SecureString` variants are mutually exclusive. |

The three authentication families are mutually exclusive. A certificate-based call creates a signed client assertion; it does not send a client secret.

## Examples

Exchange an incoming API token using a secret:

```powershell
$downstream = Get-EntraIDTokenOnBehalfOf `
  -TenantId $tenantId -ClientId $middleTierClientId `
  -UserAssertion $incomingAccessToken `
  -Scope 'https://graph.microsoft.com/User.Read' `
  -ClientSecret $middleTierSecret
```

Use a certificate from the current user's Windows store:

```powershell
Get-EntraIDTokenOnBehalfOf `
  -TenantId $tenantId -ClientId $middleTierClientId `
  -UserAssertion $incomingAccessToken `
  -Scope 'api://downstream-api-id/access_as_user' `
  -CertificateThumbprint 'A1B2C3D4E5F6...'
```

Use a cross-platform PFX and a `SecureString` password:

```powershell
$pfxPassword = Read-Host 'PFX password' -AsSecureString
Get-EntraIDTokenOnBehalfOf `
  -TenantId $tenantId -ClientId $middleTierClientId `
  -UserAssertion $incomingAccessToken `
  -Scope 'https://graph.microsoft.com/User.Read Mail.Read' `
  -PfxPath './middle-tier.pfx' -PfxPasswordSecureString $pfxPassword
```

## Request and response behavior

Before sending a request, the command decodes the JWT claims and requires `aud` to contain the supplied `ClientId`. This is an early guard against accidental misuse; Entra performs the authoritative signature, issuer, expiry, consent, and policy validation.

The command POSTs to the v2 token endpoint with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<UserAssertion>`, `requested_token_use=on_behalf_of`, `client_id=<middle-tier client ID>`, and the requested downstream `scope`. With certificate authentication, it also sends `client_assertion_type` and a short-lived RS256 client assertion.

It returns Entra's token response object unchanged; use `access_token` only for the requested downstream resource.

## Errors and troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| `UserAssertion must be an access token issued...` | Pass an access token for this middle tier, not an ID token or an access token for another resource. |
| Certificate not found/no private key/not valid | Verify store/path, thumbprint, PFX password, certificate validity, private-key access, and that the certificate is RSA. |
| PFX cannot load on macOS/Linux | Install OpenSSL or use a PFX compatible with the platform's .NET crypto provider. |
| `invalid_grant` | The incoming user token may be expired, invalid, from the wrong tenant, blocked by policy, or unsuitable for OBO. |
| `invalid_client` | Verify the secret/certificate is registered on the middle-tier app and is not expired. |
| Consent/scope error | Add the downstream delegated permission to the middle-tier app and obtain the required user/admin consent. |

## Security notes

Treat `UserAssertion`, client secrets, PFX files, and PFX passwords as credentials. `SecureString` options are convenient input forms, not a security boundary; values are converted only briefly for use and not intentionally logged or persisted. Do not place assertions or secrets in transcript files, URLs, source code, or CI logs. Restrict PFX filesystem permissions and prefer hardware-backed certificates on Windows when available.

## Verbose diagnostics

Use `-Verbose` to see the OBO stages, decoded assertion audience, selected secret/certificate input, downstream scope, token endpoint, and response metadata:

```powershell
Get-EntraIDTokenOnBehalfOf -TenantId $tenantId -ClientId $middleTierClientId `
  -ClientSecretSecureString $secret -UserAssertion $userAccessToken `
  -Scope 'https://graph.microsoft.com/User.Read' -Verbose
```

The user assertion, client secret, certificate assertion, and returned access token are represented only by redacted lengths. Certificate paths and non-sensitive request fields remain visible to make each step easy to follow.
