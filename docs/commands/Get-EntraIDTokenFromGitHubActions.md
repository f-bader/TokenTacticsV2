# Get-EntraIDTokenFromGitHubActions

## Synopsis

Obtains a GitHub Actions OIDC token from the workflow runtime, then exchanges it for an Entra ID application access token.

## Syntax

```powershell
Get-EntraIDTokenFromGitHubActions -TenantId <String> -ClientId <String> `
  [-Scope <String>] [-Audience <String>]
```

## Prerequisites and Entra setup

Run within a GitHub Actions job and grant that job `id-token: write`. Create an Entra app registration with the required application permissions and admin consent. Add a federated identity credential for the repository, branch, tag, pull request, or GitHub environment that will run the job. Its issuer, subject, and audience must match GitHub's issued token. The default audience requested by this command is `api://AzureADTokenExchange`.

For GitHub's exact subject shapes and credential configuration, use GitHub's OIDC claim documentation and inspect a token only in a safe test environment. A common branch subject is `repo:OWNER/REPOSITORY:ref:refs/heads/BRANCH`.

```yaml
permissions:
  id-token: write
  contents: read
```

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `TenantId` | Yes | Tenant domain or ID for the Entra v2 token endpoint. |
| `ClientId` | Yes | Application (client) ID configured with the GitHub federated credential. |
| `Scope` | No | One application `/.default` scope. Defaults to `https://graph.microsoft.com/.default`. |
| `Audience` | No | Audience supplied to GitHub's OIDC endpoint. Defaults to `api://AzureADTokenExchange`; it must match Entra's federated credential. |

## Examples

Acquire a Microsoft Graph application token in a workflow:

```powershell
$response = Get-EntraIDTokenFromGitHubActions `
  -TenantId $env:AZURE_TENANT_ID `
  -ClientId $env:AZURE_CLIENT_ID `
  -Scope 'https://graph.microsoft.com/.default'
$response.access_token
```

Request an Azure Resource Manager token:

```powershell
Get-EntraIDTokenFromGitHubActions `
  -TenantId 'contoso.onmicrosoft.com' `
  -ClientId '00000000-0000-0000-0000-000000000000' `
  -Scope 'https://management.azure.com/.default'
```

## Behavior and output

The cmdlet reads `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, requests an OIDC token with the selected audience, then calls `Get-EntraIDTokenFromFederatedCredential`. It returns the Entra token response; it does not return or persist the GitHub JWT.

## Errors and troubleshooting

- **OIDC environment variables are unavailable**: run in a GitHub Actions job, not locally, and add `id-token: write` at workflow or job level.
- **GitHub Actions did not return an OIDC token**: check the job permissions and that the Actions runtime endpoint is reachable.
- **Entra token request failed**: the federated credential likely does not match GitHub's issuer, subject, or `api://AzureADTokenExchange` audience. Confirm the repository/environment/ref used by this run is covered, and ensure permission consent was granted.

## Security and platform notes

The GitHub runtime token is short lived and is passed directly to Entra; the cmdlet does not write it to disk or log it. It works on Windows, Linux, and macOS GitHub-hosted or self-hosted runners where PowerShell 7 and the GitHub OIDC runtime variables are available. Use least-privilege workflow permissions and restrict Entra credentials to a precise repository/ref or protected environment.
