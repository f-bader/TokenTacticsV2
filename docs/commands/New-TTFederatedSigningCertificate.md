# New-TTFederatedSigningCertificate

## Synopsis

Creates an RSA self-signed signing certificate and writes its private key as a password-protected PFX for a custom OIDC federated credential provider.

## Syntax

```powershell
New-TTFederatedSigningCertificate -PfxPath <String> `
  (-PfxPassword <String> | -PfxPasswordSecureString <SecureString>) `
  [-Subject <String>] [-KeyLength <Int32>] [-NotAfter <DateTime>] `
  [-PublicCertificatePath <String>]
```

## Prerequisites and setup

Choose and host the stable public HTTPS issuer URL before running this command. The
issuer URL is part of the Entra trust relationship; see the custom OIDC scenario
guide for the Cloudflare named-tunnel and Azure Storage options. Generate the PFX
only after that URL is finalized, then use the same issuer for metadata and assertions.

PowerShell 7 is required. The command uses .NET cryptography where supported and falls back to OpenSSL on platforms whose providers cannot create/export the certificate. Install OpenSSL when running on macOS or when the .NET provider cannot complete the operation.

The PFX is the private signing material for `New-TTFederatedClientAssertion`. It is not uploaded to Entra and is not part of the public OIDC metadata. A self-signed certificate is sufficient because Entra verifies signatures using the JWKS you publish, rather than trusting a public certificate authority.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `PfxPath` | Yes | Destination PFX file. Parent directories are created when absent. |
| `PfxPassword` | One password form | Plaintext PFX export password. |
| `PfxPasswordSecureString` | One password form | `SecureString` PFX export password. |
| `Subject` | No | Certificate subject. Defaults to `CN=TokenTactics Federated Issuer`. |
| `KeyLength` | No | RSA size: `2048` (default), `3072`, or `4096`. |
| `NotAfter` | No | Certificate expiry; defaults to one year from creation and must be in the future. |
| `PublicCertificatePath` | No | Optional path for a DER-encoded public `.cer` export. |

## Examples

Create a default 2048-bit PFX and public certificate:

```powershell
$password = Read-Host 'PFX password' -AsSecureString
New-TTFederatedSigningCertificate `
  -PfxPath './issuer-signing.pfx' `
  -PfxPasswordSecureString $password `
  -PublicCertificatePath './issuer-signing.cer'
```

Create a 3072-bit PFX with explicit subject and lifetime:

```powershell
New-TTFederatedSigningCertificate `
  -PfxPath '/secure/issuer.pfx' -PfxPassword 'development-only-password' `
  -Subject 'CN=Contoso Build Issuer' -KeyLength 3072 `
  -NotAfter (Get-Date).AddMonths(6)
```

## Behavior and output

The command creates a digital-signature RSA certificate, exports it as PFX, and optionally exports its public certificate. It returns an object with `Thumbprint`, `PfxPath`, `PublicCertificatePath`, and `NotAfter`. Use the same PFX later to produce the metadata and assertions; rotating it requires publishing a new JWKS key before using assertions signed with that key.

## Errors and troubleshooting

- **NotAfter must be in the future**: select a later expiration date.
- **Unable to create a self-signed PFX**: install/put `openssl` on `PATH`, particularly on macOS or systems whose .NET provider cannot create self-signed certificates.
- **OpenSSL failed to create/export the PFX**: check write permission to the PFX parent directory and that the selected OpenSSL build supports RSA/PFX operations.

## Security and platform notes

Keep the PFX in a private, access-controlled location and rotate it before expiry. Plaintext password input is supported for PowerShell usability but is not secure storage; prefer secret injection or `SecureString` for interactive entry, and never place either in source control. Certificate creation works across Windows, Linux, and macOS with .NET or the OpenSSL fallback. A Windows TPM certificate created separately can also be used by the subsequent metadata/assertion commands, but this command itself outputs a portable PFX, not a TPM key.
