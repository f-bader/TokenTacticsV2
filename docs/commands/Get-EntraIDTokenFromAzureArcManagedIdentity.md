# Get-EntraIDTokenFromAzureArcManagedIdentity

## Synopsis

Retrieves a token from an Azure Arc-enabled server's local managed-identity endpoint, including Azure Arc's challenge-file authentication step.

## Syntax

```powershell
Get-EntraIDTokenFromAzureArcManagedIdentity [-Resource <String>] [-ApiVersion <String>]
```

## Prerequisites and setup

Use this command on an Azure Arc-enabled Windows or Linux server with a system-assigned or user-assigned managed identity enabled. The Arc agent provides the `IDENTITY_ENDPOINT` environment variable. Assign Azure RBAC roles and/or resource-specific permissions to that managed identity before requesting a token.

No tenant ID, client ID, secret, certificate, or federated credential is supplied: identity selection is performed by the Arc endpoint. This command is not an OAuth federation exchange and is not designed for macOS or non-Arc hosts.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `Resource` | No | Resource URI requested from the local endpoint. Defaults to `https://management.azure.com/`. |
| `ApiVersion` | No | Arc managed-identity endpoint API version. Defaults to `2020-06-01`. |

## Examples

Get an Azure Resource Manager token:

```powershell
$response = Get-EntraIDTokenFromAzureArcManagedIdentity
$response.access_token
```

Request a Microsoft Graph resource token:

```powershell
Get-EntraIDTokenFromAzureArcManagedIdentity -Resource 'https://graph.microsoft.com/'
```

## Behavior and output

The command validates that `IDENTITY_ENDPOINT` resolves to `localhost`, `127.0.0.1`, or `::1`, then sends a metadata request. Azure Arc typically responds with a `WWW-Authenticate` challenge naming a local secret file. The command reads that file, repeats the request with its `Basic` authorization value, and returns the endpoint token response. The secret is not returned or persisted.

## Errors and troubleshooting

- **IDENTITY_ENDPOINT is not set**: the command is not running in the environment supplied by an Arc managed identity. Confirm that the Arc agent and identity are enabled, then start a new shell if necessary.
- **IDENTITY_ENDPOINT must be a loopback endpoint**: do not override the environment variable with a remote address; this guard protects the local challenge secret.
- **Inaccessible challenge secret file**: the process identity cannot read the file supplied by Arc, or the agent endpoint returned an invalid challenge. Check Arc agent health and run as the appropriate local account.
- **Managed identity request failed**: verify the resource URI, managed-identity assignment, RBAC/resource permissions, and that Arc can reach Entra.

## Security and platform notes

The challenge file is an Arc-local secret and must never be copied, printed, or committed. The command limits the endpoint to loopback before processing it and clears its in-memory secret reference when finished. It is intended for Azure Arc-enabled Windows and Linux servers; it is not a general Azure VM IMDS command and has no macOS support.
