# New-TTFederatedClientAssertion

## Synopsis

Creates a short-lived RS256-signed OIDC JWT from a local PFX or Windows certificate-store/TPM key for exchange through an Entra custom federated credential.

## Syntax

```powershell
New-TTFederatedClientAssertion -Issuer <Uri> -Subject <String> `
  (-CertificateThumbprint <String> [-CertStoreLocation <String>] | `
   -PfxPath <String> [-PfxPassword <String> | -PfxPasswordSecureString <SecureString>]) `
  [-Audience <String>] [-LifetimeMinutes <Int32>]
```

## Prerequisites and custom issuer setup

Before issuing an assertion, publish OIDC discovery/JWKS for this signing key with `New-TTFederatedIssuerMetadata`, using the same HTTPS issuer. Configure the workload application's **Other issuer** federated credential in Entra to exactly match this command's issuer, subject, and audience. The public JWKS must expose the signing certificate's key ID.

An assertion by itself is not an access token. Pass it to `Get-EntraIDTokenFromFederatedCredential` along with the tenant, application client ID, and a `/.default` scope.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `Issuer` | Yes | HTTPS issuer URL. A trailing slash is removed before signing. Must match discovery and Entra configuration. |
| `Subject` | Yes | Workload subject. Must exactly match Entra's federated credential. |
| `Audience` | No | Assertion audience. Defaults to `api://AzureADTokenExchange`. |
| `LifetimeMinutes` | No | Assertion lifetime from 1 to 10 minutes; default is 5. |
| `CertificateThumbprint` | One signing-key form | Windows certificate-store/TPM RSA certificate thumbprint. |
| `CertStoreLocation` | No | `Cert:\CurrentUser\My` (default) or `Cert:\LocalMachine\My`; thumbprint form only. |
| `PfxPath` | One signing-key form | RSA PFX path. |
| `PfxPassword` | PFX plaintext set | Plaintext PFX password. |
| `PfxPasswordSecureString` | PFX secure set | `SecureString` PFX password. |

## Examples

Create and exchange an assertion from a PFX:

```powershell
$password = Read-Host 'PFX password' -AsSecureString
$assertion = New-TTFederatedClientAssertion `
  -Issuer 'https://oidc.example.com' -Subject 'contoso-build-agent' `
  -PfxPath './issuer-signing.pfx' -PfxPasswordSecureString $password

$token = Get-EntraIDTokenFromFederatedCredential `
  -TenantId 'contoso.onmicrosoft.com' `
  -ClientId '00000000-0000-0000-0000-000000000000' `
  -FederatedToken $assertion `
  -Scope 'https://graph.microsoft.com/.default'
```

Use a TPM-backed certificate on Windows:

```powershell
New-TTFederatedClientAssertion `
  -Issuer 'https://oidc.contoso.example' -Subject 'build-host-01' `
  -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -LifetimeMinutes 3
```

## Behavior and output

Returns a compact JWT string, signed with RS256. The header contains `alg`, `typ`, and an `x5t#S256` key ID derived from the signing certificate. The payload has `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, and a unique `jti`; `exp` is limited to 1–10 minutes after issuance. Each invocation uses a fresh `jti`.

## Errors and troubleshooting

- **Issuer must be an HTTPS URL**: use the same stable public issuer configured in the OIDC discovery document and Entra credential.
- **Certificate not found / no accessible private key**: correct the PFX path/password or certificate thumbprint/store; the key must be RSA and usable for signing.
- **OpenSSL could not sign the JWT**: on a platform using the OpenSSL PFX fallback, ensure OpenSSL is installed and the PFX key can be extracted. PSS signing is not used by this command.
- **Entra rejects the exchanged assertion**: decode the JWT without exposing it publicly and compare `iss`, `sub`, `aud`, `exp`, and header key ID to your configuration/JWKS. Confirm the issuer's discovery and keys are publicly reachable over HTTPS.

## Security and platform notes

The output JWT is a bearer assertion: treat it as sensitive until its short expiry. The command does not persist it. PFX signing works across Windows, Linux, and macOS, using an OpenSSL fallback when needed; Windows certificate-store/TPM signing is Windows-only. Keep PFX files and passwords in access-controlled storage, use the shortest practical lifetime, rotate public JWKS before changing the signer, and never expose the private key through the metadata host.
