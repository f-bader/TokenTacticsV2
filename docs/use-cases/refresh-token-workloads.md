# Refresh tokens for Microsoft cloud workloads

The refresh-token wrappers request a new resource-specific access token from
Microsoft Entra ID. They do not change the permissions granted to the refresh
token or bypass Conditional Access. The effective permissions and claims remain
subject to the tenant, client, resource provider, and current policy.

```mermaid
sequenceDiagram
    participant R as Authorized researcher or automation
    participant C as TokenTactics refresh wrapper
    participant E as Entra ID token endpoint
    participant W as Microsoft workload

    R->>C: Supply refresh token and tenant
    C->>E: grant_type=refresh_token with workload scope
    E-->>C: Resource-specific access token
    C-->>R: Summary; raw response saved globally
    R->>W: Call only the named workload
    W-->>R: Authorized workload response or claims challenge
```

## Common pattern

```powershell
Invoke-RefreshToMSGraphToken `
    -TenantId 'contoso.onmicrosoft.com' `
    -RefreshToken $response.refresh_token `
    -UseCAE

$graphToken = $MSGraphToken
```

`-Domain` is the required tenant parameter name on the wrappers; `-TenantId` and
`-ResourceTenant` are compatibility aliases. If `-RefreshToken` is omitted, the
wrapper reads `$response.refresh_token`. Each wrapper saves its raw response to a
workload-specific global variable and emits a short token summary.

All wrappers accept `-ClientId`, `-CustomUserAgent`, `-Device`, `-Browser`, and
`-UseCAE`. User-agent selection is only request metadata; it is not a device-trust
mechanism. `-UseCAE` requests the `cp1` client capability on the v2 endpoint.
The Device Registration wrapper uses the v1 endpoint, so it ignores `-UseCAE`
with a warning and does not send CAE claims.

## Workload matrix

| Command | Default scope or resource | Output variable |
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
| `Invoke-RefreshToSharePointToken` | `https://<tenant>[-admin].sharepoint.com/Sites.FullControl.All` | `$SharePointToken` |
| `Invoke-RefreshToOneDriveToken` | `https://officeapps.live.com/.default` | `$OneDriveToken` |
| `Invoke-RefreshToYammerToken` | `https://www.yammer.com/.default` | `$YammerToken` |
| `Invoke-RefreshToDeviceRegistrationToken` | `openid` with device-registration contract | `$DeviceRegistrationToken` |

For SharePoint, pass `-SharePointTenantName` and optionally
`-SharePointUseAdmin`:

```powershell
Invoke-RefreshToSharePointToken `
    -Domain 'contoso.onmicrosoft.com' `
    -RefreshToken $response.refresh_token `
    -SharePointTenantName 'contoso' `
    -SharePointUseAdmin
```

## Validate before use

Decode a token locally with `ConvertFrom-JWTtoken` and inspect `aud`, `iss`, `tid`,
`scp` or `roles`, `upn`/`preferred_username`, and the expiration fields. A successful
token request does not prove that a later resource call is authorized.

```powershell
$claims = ConvertFrom-JWTtoken $MSGraphToken.access_token
$claims | Select-Object tid, aud, scp, roles, ExpirationDate, ValidForHours
```

For CAE-capable sessions, a resource provider can reject an unexpired token and
return a claims challenge. See the [Continuous Access Evaluation guide](./continuous-access-evaluation.md).

## Security and failure tests

- Keep refresh tokens out of transcripts, process arguments, logs, and source
  control. Prefer an approved secret store for unattended tests.
- Confirm the token's audience before sending it to a workload.
- Test wrong tenant, invalid or revoked refresh token, insufficient consent, and
  a resource-specific permission failure.
- Test a CAE claims challenge with a CAE-aware client and record whether the
  resource provider supports the requested capability.

See the [refresh-token command reference](../commands/refresh-token-workloads.md).
