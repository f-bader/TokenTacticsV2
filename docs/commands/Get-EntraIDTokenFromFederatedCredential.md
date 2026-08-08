# Get-EntraIDTokenFromFederatedCredential

## Synopsis

Exchanges an externally issued OIDC JSON Web Token (JWT) for an Entra ID application access token through the OAuth 2.0 client-credentials grant with a `client_assertion`.

## Syntax

```powershell
Get-EntraIDTokenFromFederatedCredential -TenantId <String> -ClientId <String> `
  -FederatedToken <String> [-Scope <String>]

Get-EntraIDTokenFromFederatedCredential -TenantId <String> -ClientId <String> `
  -FederatedTokenSecureString <SecureString> [-Scope <String>]

Get-EntraIDTokenFromFederatedCredential -TenantId <String> -ClientId <String> `
  -FederatedTokenPath <String> [-Scope <String>]
```

## Prerequisites and Entra setup

Create an app registration for the workload, grant its required **application** permissions, and grant tenant admin consent where required. Under **Certificates & secrets > Federated credentials**, create a federated identity credential whose issuer (`iss`), subject (`sub`), and audience (`aud`) exactly match the external JWT. The usual audience is `api://AzureADTokenExchange`.

This command does not register the credential or validate its claims locally; Entra performs that trust validation. The requested scope must be exactly one resource followed by `/.default`.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `TenantId` | Yes | Tenant domain or ID used to construct the Entra v2 token endpoint. |
| `ClientId` | Yes | Application (client) ID of the Entra workload app. |
| `FederatedToken` | One token source | Plaintext external JWT. Cannot be combined with the other token-source parameters. |
| `FederatedTokenSecureString` | One token source | `SecureString` external JWT. It is converted only for the request. |
| `FederatedTokenPath` | One token source | Path to a file containing the external JWT. Leading/trailing whitespace is removed. |
| `Scope` | No | Application resource scope. Defaults to `https://graph.microsoft.com/.default`; must be one `/.default` scope. |

## Examples

Use a JWT received directly from an external OIDC provider:

```powershell
$token = Get-EntraIDTokenFromFederatedCredential `
  -TenantId 'contoso.onmicrosoft.com' `
  -ClientId '00000000-0000-0000-0000-000000000000' `
  -FederatedToken $externalJwt `
  -Scope 'https://management.azure.com/.default'
$token.access_token
```

Read a projected workload token from a file:

```powershell
Get-EntraIDTokenFromFederatedCredential `
  -TenantId $env:AZURE_TENANT_ID -ClientId $env:AZURE_CLIENT_ID `
  -FederatedTokenPath '/var/run/secrets/tokens/oidc-token' `
  -Scope 'https://graph.microsoft.com/.default'
```

## Behavior and output

Posts `grant_type=client_credentials`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, and the external JWT to `https://login.microsoftonline.com/<TenantId>/oauth2/v2.0/token`. It returns Entra's token response object, normally including `access_token`, `token_type`, `expires_in`, and `ext_expires_in`.

## Errors and troubleshooting

- **Federated token file was not found**: supply an existing file path and ensure the current identity can read it.
- **Scope must contain exactly one resource**: use a single application scope such as `https://graph.microsoft.com/.default`, not delegated scopes such as `User.Read`.
- **Entra token request failed**: compare the JWT's decoded `iss`, `sub`, and `aud` to the federated credential configuration; verify the app ID, tenant, permissions, and consent. Also verify the external JWT has not expired.

## Security and platform notes

Plaintext, `SecureString`, and token-file inputs are convenience mechanisms, not a PowerShell security boundary. Do not log or commit JWTs; they can be exchanged while valid. The command does not persist the supplied assertion and does not include request bodies in its own exception messages. It runs on PowerShell 7 on Windows, Linux, and macOS.
