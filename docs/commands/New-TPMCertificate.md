# New-TPMCertificate

Creates a non-exportable RSA certificate backed by the Windows Platform Crypto
Provider. The certificate is placed in a personal certificate store and can be
used by `Get-EntraIDTokenFromCertificate`.

## Syntax

```powershell
$certificate = New-TPMCertificate `
    -Subject 'CN=EntraID-TPM-Auth' `
    -PublicKeyPath 'C:\Temp\EntraID-TPM-Auth.cer'
```

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-Subject` | Certificate subject. Required. |
| `-CertStoreLocation` | `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`. |
| `-KeyLength` | `2048`, `3072`, or `4096`; defaults to 2048. |
| `-NotAfter` | Expiration date; defaults to two years from creation. |
| `-PublicKeyPath` | Optional `.cer` path for the public certificate only. |

The command requires Windows, a provisioned TPM, and the Microsoft Platform Crypto
Provider. `Cert:\LocalMachine\My` generally requires elevation. The private key is
non-exportable; upload only the generated public `.cer` file to the app registration.

The command supports `ShouldProcess`; review the target store before confirming.
See the [certificate identity guide](../use-cases/certificate-application-identity.md).
