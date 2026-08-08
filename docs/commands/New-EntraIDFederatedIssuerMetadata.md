# New-EntraIDFederatedIssuerMetadata

## Synopsis

Generates the public OpenID Connect discovery document, JWKS, and local issuer
configuration required to make a certificate-backed custom federated credential
provider discoverable by Entra ID.

## Syntax

    New-EntraIDFederatedIssuerMetadata -Issuer <Uri> -Subject <String> -OutputPath <String> -PfxPath <String> [-PfxPassword <String> | -PfxPasswordSecureString <SecureString>] [-Audience <String>]
    New-EntraIDFederatedIssuerMetadata -Issuer <Uri> -Subject <String> -OutputPath <String> -CertificateThumbprint <String> [-CertStoreLocation <String>] [-Audience <String>]

## Custom issuer setup order

Choose the hosting option and stable HTTPS issuer URL before creating the
certificate. The exact issuer value must be repeated in Entra, the discovery
document, and every assertion.

1. Choose a stable custom hostname routed through a Cloudflare named tunnel, or
   deploy infra/oidc-static-website.bicep to create an Azure Storage static website.
   The [custom OIDC scenario guide](../use-cases/custom-oidc-provider.md) contains
   Azure CLI and Az PowerShell deployment commands.
2. Create a signing PFX with New-EntraIDFederatedSigningCertificate, or use an existing
   RSA PFX or Windows certificate-store/TPM certificate.
3. Run this command and publish the generated directory through the chosen URL. It
   must serve /.well-known/openid-configuration and /keys.json without authentication.
   Keep the PFX and private key outside the public directory.
4. In the app registration, create an Other issuer federated credential with the
   generated issuer, exact subject, and exact audience. The default audience is
   api://AzureADTokenExchange. Assign application permissions and grant consent.
5. Use New-EntraIDFederatedClientAssertion with the same issuer, subject, and signing key,
   then exchange it with Get-EntraIDTokenFromFederatedCredential.

Only discovery/JWKS files are public. Never host the PFX, issuer configuration file,
private key, or an unauthenticated signing API.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| Issuer | Yes | Stable HTTPS issuer URL. The trailing slash is removed in generated metadata. |
| Subject | Yes | Workload subject that must match the Entra federated credential and assertion. |
| OutputPath | Yes | Directory to receive public metadata and local configuration. |
| Audience | No | Assertion audience. Defaults to api://AzureADTokenExchange. |
| CertificateThumbprint | One signing-key form | RSA certificate thumbprint from a Windows certificate store. |
| CertStoreLocation | No | Cert:\CurrentUser\My or Cert:\LocalMachine\My; applies to thumbprint input. |
| PfxPath | One signing-key form | Existing RSA PFX path. |
| PfxPassword | PFX plaintext set | Plaintext PFX password. |
| PfxPasswordSecureString | PFX secure set | SecureString PFX password. |

## Examples

Generate metadata from a portable PFX:

    $password = Read-Host 'PFX password' -AsSecureString
    New-EntraIDFederatedIssuerMetadata -Issuer 'https://oidc.example.com' -Subject 'contoso-build-agent' -OutputPath './oidc-public' -PfxPath './issuer-signing.pfx' -PfxPasswordSecureString $password

Generate metadata using a Windows certificate-store certificate:

    New-EntraIDFederatedIssuerMetadata -Issuer 'https://oidc.contoso.example' -Subject 'arc-build-host-01' -OutputPath 'C:\oidc-public' -CertificateThumbprint $certificate.Thumbprint

## Behavior and generated files

The command requires an HTTPS issuer and an RSA public key. It writes:

- .well-known/openid-configuration: issuer, JWKS URI, `id_token` response type,
  public subject type, and RS256 discovery information.
- keys.json: a JWKS with the RSA public key, x5c, and a stable SHA-256-derived key ID.
- issuer-config.json: issuer, subject, audience, and key ID for local reference. Treat
  this as local configuration and do not publish it unless its contents meet your
  operational policy.

It returns Issuer, Subject, Audience, KeyId, and OutputPath.
OutputPath is normalized to an absolute path based on PowerShell's current
`Get-Location`. The result also includes
DiscoveryPath, JwksPath, ConfigurationPath, and GeneratedFiles so you can verify
exactly what was written.

## Errors and troubleshooting

- Issuer must be an HTTPS URL: use a stable public HTTPS address.
- `.well-known` is a hidden directory on many platforms. Use
  `Get-ChildItem -Force -Recurse` or `Test-Path` when checking the generated
  discovery file; its required URL is `/.well-known/openid-configuration` (no
  `.json` suffix).
- PFX not found, no accessible private key, or no RSA public key: verify path/password
  or certificate-store access and use an RSA signing certificate.
- Entra cannot validate a credential: compare issuer including path, subject, audience,
  discovery URL, and jwks_uri. Ensure both public JSON URLs are reachable anonymously.

## Security and platform notes

PFX input is cross-platform; macOS PFX loading can require OpenSSL. Thumbprint/store
input is Windows-only. The metadata contains public key material, but issuer-config.json
is intended for local workflow reference. Protect the signing PFX separately and
rotate by publishing the replacement key before signing with it.

## Verbose diagnostics

Add `-Verbose` to see issuer/subject/audience validation, PowerShell-relative output-path resolution, certificate loading, and every generated file:

```powershell
New-EntraIDFederatedIssuerMetadata -Issuer $issuer -Subject $subject `
  -OutputPath $outputPath -PfxPath $pfxPath -PfxPasswordSecureString $password -Verbose
```

The PFX password, private key, and certificate contents are never logged. The resolved output directory, discovery/JWKS/configuration paths, and public key ID are shown so hosting problems are easy to diagnose.
