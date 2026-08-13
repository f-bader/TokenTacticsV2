# Exported command reference

This index covers every canonical function exported by `TokenTactics.psd1`. Use
the [scenario guides](../README.md) for end-to-end setup and the command pages for
parameter behavior and focused examples. Compatibility aliases are documented in
the relevant grouped pages but are not repeated as separate canonical commands.

## Interactive, cookie, and brokered authentication

See [interactive authentication commands](./authentication.md).

- [Get-EntraIDTokenFromDeviceCode](./authentication.md#get-entraidtokenfromdevicecode)
- [Get-EntraIDAuthorizationCode](./authentication.md#get-entraidauthorizationcode)
- [Get-EntraIDTokenFromAuthorizationCode](./authentication.md#get-entraidtokenfromauthorizationcode)
- [Get-EntraIDTokenFromCookie](./authentication.md#get-entraidtokenfromcookie)
- [Get-EntraIDTokenFromESTSCookie](./authentication.md#get-entraidtokenfromestscookie)
- [Get-EntraIDTokenFromRefreshTokenCredentialCookie](./authentication.md#get-entraidtokenfromrefreshtokencredentialcookie)
- [Get-EntraIDTokenFromSCCAUTHCookie](./authentication.md#get-entraidtokenfromsccauthcookie)
- [Get-EntraIDTokenFromNestedAppAuth](./authentication.md#get-entraidtokenfromnestedappauth)

## Passkey and FIDO2

See [passkey and FIDO2 commands](./passkey-and-fido2.md).

- [Invoke-EntraIDPasskeyLogin](./passkey-and-fido2.md#invoke-entraidpasskeylogin)
- [Get-EntraIDFido2Challenge](./passkey-and-fido2.md#get-entraidfido2challenge)
- [Get-WindowsHelloFidoAssertion](./passkey-and-fido2.md#get-windowshellofidoassertion)
- [Invoke-EntraIDPasskeyAssertionLogin](./passkey-and-fido2.md#invoke-entraidpasskeyassertionlogin)
- [New-EntraIDUserHandle](./passkey-and-fido2.md#new-entraiduserhandle)

## Application and workload authentication

- [Get-EntraIDTokenFromCertificate](./Get-EntraIDTokenFromCertificate.md)
- [Get-EntraIDTokenFromClientSecret](./Get-EntraIDTokenFromClientSecret.md)
- [Get-EntraIDTokenOnBehalfOf](./Get-EntraIDTokenOnBehalfOf.md)
- [Get-EntraIDTokenFromFederatedCredential](./Get-EntraIDTokenFromFederatedCredential.md)
- [Get-EntraIDTokenFromGitHubActions](./Get-EntraIDTokenFromGitHubActions.md)
- [Get-EntraIDTokenFromAzureArcManagedIdentity](./Get-EntraIDTokenFromAzureArcManagedIdentity.md)
- [New-TPMCertificate](./New-TPMCertificate.md)
- [New-EntraIDImplicitAuthorizationUrl](./New-EntraIDImplicitAuthorizationUrl.md)
- [ConvertFrom-EntraIDImplicitRedirect](./ConvertFrom-EntraIDImplicitRedirect.md)
- [New-EntraIDFederatedSigningCertificate](./New-EntraIDFederatedSigningCertificate.md)
- [New-EntraIDFederatedIssuerMetadata](./New-EntraIDFederatedIssuerMetadata.md)
- [New-EntraIDFederatedClientAssertion](./New-EntraIDFederatedClientAssertion.md)

## Refresh-token workload access

See the [refresh-token workload commands](./refresh-token-workloads.md) and its
[scenario guide](../use-cases/refresh-token-workloads.md).

- [Invoke-RefreshToSubstrateToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToMSManageToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToMSTeamsToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToOfficeManagementToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToOutlookToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToMSGraphToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToGraphToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToOfficeAppsToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToAzureCoreManagementToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToAzureStorageToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToAzureKeyVaultToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToAzureManagementToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToMAMToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToDODMSGraphToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToSharePointToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToOneDriveToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToYammerToken](./refresh-token-workloads.md#command-matrix)
- [Invoke-RefreshToDeviceRegistrationToken](./refresh-token-workloads.md#command-matrix)

## Token and session utilities

See [token and session utilities](./token-and-session-utilities.md).

- [Clear-Token](./token-and-session-utilities.md#clear-token)
- [ConvertFrom-JWTtoken](./token-and-session-utilities.md#convertfrom-jwttoken)
- [ConvertTo-PEMPrivateKey](./token-and-session-utilities.md#convertto-pemprivatekey)
- [Get-ForgedUserAgent](./token-and-session-utilities.md#get-forgeduseragent)
- [Get-TenantID](./token-and-session-utilities.md#get-tenantid)

## Compatibility aliases

These aliases remain exported for existing scripts. New scripts should use the
canonical function names above.

| Alias | Canonical command |
| --- | --- |
| `Parse-JWTtoken` | `ConvertFrom-JWTtoken` |
| `Forge-UserAgent` | `Get-ForgedUserAgent` |
| `RefreshTo-SubstrateToken` | `Invoke-RefreshToSubstrateToken` |
| `RefreshTo-MSManageToken` | `Invoke-RefreshToMSManageToken` |
| `RefreshTo-MSTeamsToken` | `Invoke-RefreshToMSTeamsToken` |
| `RefreshTo-OfficeManagementToken` | `Invoke-RefreshToOfficeManagementToken` |
| `RefreshTo-OutlookToken` | `Invoke-RefreshToOutlookToken` |
| `RefreshTo-MSGraphToken` | `Invoke-RefreshToMSGraphToken` |
| `RefreshTo-GraphToken` | `Invoke-RefreshToGraphToken` |
| `RefreshTo-OfficeAppsToken` | `Invoke-RefreshToOfficeAppsToken` |
| `RefreshTo-AzureCoreManagementToken` | `Invoke-RefreshToAzureCoreManagementToken` |
| `RefreshTo-AzureManagementToken` | `Invoke-RefreshToAzureManagementToken` |
| `RefreshTo-MAMToken` | `Invoke-RefreshToMAMToken` |
| `RefreshTo-DODMSGraphToken` | `Invoke-RefreshToDODMSGraphToken` |
| `RefreshTo-SharePointToken` | `Invoke-RefreshToSharePointToken` |
| `RefreshTo-OneDriveToken` | `Invoke-RefreshToOneDriveToken` |
| `RefreshTo-YammerToken` | `Invoke-RefreshToYammerToken` |
| `RefreshTo-AzureStorageToken` | `Invoke-RefreshToAzureStorageToken` |
| `RefreshTo-AzureKeyVaultToken` | `Invoke-RefreshToAzureKeyVaultToken` |
| `RefreshTo-DeviceRegistrationToken` | `Invoke-RefreshToDeviceRegistrationToken` |
| `Get-EntraIDToken` | `Get-EntraIDTokenFromDeviceCode` |
| `Get-AzureToken` | `Get-EntraIDTokenFromDeviceCode` |
| `Get-AzureTokenFromESTSCookie` | `Get-EntraIDTokenFromESTSCookie` |
| `Get-AzureTokenFromAuthorizationCode` | `Get-EntraIDTokenFromAuthorizationCode` |
| `Get-AzureAuthorizationCode` | `Get-EntraIDAuthorizationCode` |
| `Get-AzureTokenFromCookie` | `Get-EntraIDTokenFromCookie` |
| `Get-AzureTokenFromRefreshTokenCredentialCookie` | `Get-EntraIDTokenFromRefreshTokenCredentialCookie` |
