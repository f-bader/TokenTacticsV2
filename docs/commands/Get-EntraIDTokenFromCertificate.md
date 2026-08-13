# Get-EntraIDTokenFromCertificate

Acquires an app-only Entra ID token with an RSA certificate client assertion. The
certificate private key is resolved from a Windows personal certificate store; the
corresponding public certificate must already be registered on the app.

## Syntax

```powershell
Get-EntraIDTokenFromCertificate `
    -TenantId $tenantId `
    -ClientId $clientId `
    -CertificateThumbprint $thumbprint `
    -Scope 'https://graph.microsoft.com/.default'
```

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-TenantId` | Tenant GUID or domain. |
| `-ClientId` | App registration client ID. |
| `-CertificateThumbprint` | RSA certificate thumbprint in the personal store. |
| `-CertStoreLocation` | Defaults to `Cert:\CurrentUser\My`; use LocalMachine only with required permissions. |
| `-Scope` | One resource followed by `/.default`. |

The command returns the OAuth response and saves it in `$response`. It requires an
RSA private key that is usable by the current process. TPM-backed certificates can
sign without exporting the private key.

## Security checks

- Register only the public `.cer` certificate on the app registration.
- Verify the thumbprint, validity period, key algorithm, and private-key access.
- Grant only the required application permissions and admin consent.
- Protect `$response` and clear it when the test ends.

See the [certificate identity guide](../use-cases/certificate-application-identity.md)
and [TPM command reference](./New-TPMCertificate.md).
