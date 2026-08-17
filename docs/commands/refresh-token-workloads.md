# Refresh-token workload command reference

All commands in this page call the shared refresh-token contract. Each requires
`-Domain` and accepts `-TenantId`/`-ResourceTenant` aliases. `-RefreshToken`
defaults to `$response.refresh_token`; provide it explicitly in automation. Each
command accepts `-ClientId`, `-CustomUserAgent`, `-Device`, `-Browser`, and
`-UseCAE`, then saves a workload-specific response variable. Device Registration
uses a v1 resource contract and therefore ignores `-UseCAE` with a warning.

## Command matrix

| Command | Scope | Output variable |
| --- | --- | --- |
| `Invoke-RefreshToSubstrateToken` | `https://substrate.office.com/.default` | `$SubstrateToken` |
| `Invoke-RefreshToMSManageToken` | `https://enrollment.manage.microsoft.com/.default` | `$MSManageToken` |
| `Invoke-RefreshToMSTeamsToken` | `https://api.spaces.skype.com/.default` | `$MSTeamsToken` |
| `Invoke-RefreshToOfficeManagementToken` | `https://manage.office.com/.default` | `$OfficeManagementToken` |
| `Invoke-RefreshToOutlookToken` | `https://outlook.office365.com/.default` | `$OutlookToken` |
| `Invoke-RefreshToMSGraphToken` | `https://graph.microsoft.com/.default` | `$MSGraphToken` |
| `Invoke-RefreshToGraphToken` | `https://graph.windows.net/.default` | `$GraphToken` |
| `Invoke-RefreshToOfficeAppsToken` | `https://officeapps.live.com/.default` | `$OfficeAppsToken` |
| `Invoke-RefreshToAzureCoreManagementToken` | `https://management.core.windows.net/.default` | `$AzureCoreManagementToken` |
| `Invoke-RefreshToAzureStorageToken` | `https://storage.azure.com/.default` | `$AzureStorageToken` |
| `Invoke-RefreshToAzureKeyVaultToken` | `https://vault.azure.net/.default` | `$AzureKeyVaultToken` |
| `Invoke-RefreshToAzureManagementToken` | `https://management.azure.com/.default` | `$AzureManagementToken` |
| `Invoke-RefreshToMAMToken` | `https://intunemam.microsoftonline.com/.default` | `$MAMToken` |
| `Invoke-RefreshToDODMSGraphToken` | `https://dod-graph.microsoft.us/.default` | `$DODMSGraphToken` |
| `Invoke-RefreshToSharePointToken` | Tenant SharePoint scope | `$SharePointToken` |
| `Invoke-RefreshToOneDriveToken` | `https://officeapps.live.com/.default` | `$OneDriveToken` |
| `Invoke-RefreshToYammerToken` | `https://www.yammer.com/.default` | `$YammerToken` |
| `Invoke-RefreshToDeviceRegistrationToken` | Device-registration resource contract | `$DeviceRegistrationToken` |

## Common syntax

```powershell
Invoke-RefreshToMSGraphToken `
    -Domain 'contoso.onmicrosoft.com' `
    -RefreshToken $refreshToken `
    -UseCAE
```

The wrappers save the raw response in the workload-specific global variable and
emit a summary containing token type, scope, and expiration. The summary is not a
bearer token; use the global variable's `.access_token` property, for example
`$MSGraphToken.access_token`.

## Service-specific parameters

`Invoke-RefreshToSharePointToken` additionally accepts `-SharePointTenantName`
and `-SharePointUseAdmin`:

```powershell
Invoke-RefreshToSharePointToken `
    -Domain 'contoso.onmicrosoft.com' `
    -RefreshToken $refreshToken `
    -SharePointTenantName 'contoso' `
    -SharePointUseAdmin
```

`Invoke-RefreshToDODMSGraphToken` uses the DoD cloud endpoint and should be used
only with the corresponding authorized tenant. `Invoke-RefreshToDeviceRegistrationToken`
uses the v1 device-registration resource contract, is not a general Graph token,
and cannot request CAE claims.

## Compatibility aliases

The module also exports aliases beginning with `RefreshTo-`, such as
`RefreshTo-MSGraphToken`, `RefreshTo-MSTeamsToken`, and
`RefreshTo-AzureManagementToken`. New scripts should use the canonical
`Invoke-RefreshTo...` names. The aliases remain for existing scripts.

See the [refresh-token workload guide](../use-cases/refresh-token-workloads.md)
for claims inspection, CAE behavior, and security tests.
