# Get-EntraIDTokenFromClientSecret

## Synopsis

Requests an app-only Microsoft Entra access token using the OAuth 2.0 client-credentials grant and an application client secret.

## Syntax

```powershell
Get-EntraIDTokenFromClientSecret -TenantId <string> -ClientId <string> `
  -ClientSecret <string> [-Scope <string>]

Get-EntraIDTokenFromClientSecret -TenantId <string> -ClientId <string> `
  -ClientSecretSecureString <securestring> [-Scope <string>]
```

## Prerequisites and Entra setup

1. Create an Entra app registration and record its application/client ID.
2. Create a client secret under **Certificates & secrets** and copy its *Value*. The secret ID is not the secret value.
3. Add the required **application** permissions for the target API and grant admin consent where required.
4. Use the tenant GUID, tenant domain, or supported tenant selector as `TenantId`.

This grant represents the application, not a signed-in user. Delegated permissions such as `User.Read` do not make an app-only token usable; configure the target API's application permissions instead.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `TenantId` | Yes | Tenant GUID, domain, or supported Entra tenant selector used to construct the v2 token endpoint. |
| `ClientId` | Yes | Application (client) ID of the confidential client. |
| `ClientSecret` | One secret input | Plaintext client-secret value. Cannot be used with `ClientSecretSecureString`. |
| `ClientSecretSecureString` | One secret input | `SecureString` client-secret value. Cannot be used with `ClientSecret`. |
| `Scope` | No | One resource followed by `/.default`; defaults to `https://graph.microsoft.com/.default`. |

`Scope` must contain exactly one whitespace-delimited value ending in `/.default`, such as `https://graph.microsoft.com/.default` or `api://<resource-app-id>/.default`.

## Examples

Request a Microsoft Graph app-only token with a plaintext secret:

```powershell
$token = Get-EntraIDTokenFromClientSecret `
  -TenantId 'contoso.onmicrosoft.com' `
  -ClientId '11111111-2222-3333-4444-555555555555' `
  -ClientSecret 'secret-value' `
  -Scope 'https://graph.microsoft.com/.default'

$token.access_token
```

Request the same token when the input was collected as a `SecureString`:

```powershell
$secret = Read-Host 'Client secret' -AsSecureString
Get-EntraIDTokenFromClientSecret `
  -TenantId $tenantId -ClientId $clientId `
  -ClientSecretSecureString $secret
```

Request a token for a custom API:

```powershell
Get-EntraIDTokenFromClientSecret `
  -TenantId $tenantId -ClientId $clientId -ClientSecret $secret `
  -Scope 'api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/.default'
```

## Request and response behavior

The command POSTs form data to `https://login.microsoftonline.com/<TenantId>/oauth2/v2.0/token`. It sends `client_id`, `client_secret`, `scope`, and `grant_type=client_credentials`.

It returns Entra's token response object unchanged, normally containing `access_token`, `token_type`, `expires_in`, and `ext_expires_in`. The caller owns token caching and renewal; request a new token before it expires.

## Errors and troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| `Scope must contain exactly one resource...` | Use exactly one `/.default` scope; do not pass multiple scopes or delegated scope names. |
| `invalid_client` | Check the client ID, use the *secret value* rather than its identifier, and confirm the secret has not expired. |
| `unauthorized_client` or `invalid_scope` | The target resource/scope is wrong, or the application permission has not been granted and consented. |
| `Entra token request failed` | Inspect the Entra error code/message while keeping secrets out of copied logs. Verify tenant, app registration, network access, and consent. |

## Security notes

`SecureString` is accepted for PowerShell ergonomics, not as a security boundary. The value is converted only long enough to build the HTTPS request, is not deliberately persisted, and request bodies are excluded from the module's token-endpoint error text. Avoid putting plaintext secrets in source files, shell history, CI logs, transcripts, or command-line arguments. Prefer a secret store or a workload-federated credential for automation where practical.
