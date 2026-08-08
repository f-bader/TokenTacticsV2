# Authenticate a GitHub Actions or external workload

Use workload identity federation when the runner already has an OIDC identity and
you do not want to create a long-lived Entra client secret.

## GitHub Actions

### Entra setup

1. Create an app registration and grant its application permissions.
2. Add a federated credential under Certificates & secrets.
3. Select GitHub Actions and configure the exact organization, repository, and branch,
   tag, pull-request, or environment subject.
4. Use the standard audience api://AzureADTokenExchange.
5. Grant admin consent where required.

### Workflow setup

The job must grant the runner an ID token:

    permissions:
      id-token: write
      contents: read

Then acquire the token:

    Get-EntraIDTokenFromGitHubActions -TenantId $env:AZURE_TENANT_ID -ClientId $env:AZURE_CLIENT_ID -Scope 'https://management.azure.com/.default'

The command reads the GitHub Actions runtime URL and request token, asks for the
configured audience, and exchanges the resulting JWT with Entra. It does not need a
client secret.

## Other external providers

Use Get-EntraIDTokenFromFederatedCredential when the provider gives you a signed JWT:

    Get-EntraIDTokenFromFederatedCredential -TenantId $tenantId -ClientId $clientId -FederatedToken $oidcToken -Scope 'https://graph.microsoft.com/.default'

For a projected token file:

    Get-EntraIDTokenFromFederatedCredential -TenantId $tenantId -ClientId $clientId -FederatedTokenPath '/var/run/secrets/oidc/token' -Scope 'https://graph.microsoft.com/.default'

The issuer, subject, and audience in the JWT must exactly match the Entra federated
credential. SecureString input is available for in-memory handoff but is not a
security boundary.

## Verify and troubleshoot

Run once from an allowed GitHub subject and once from a branch/environment not listed
in the credential. The first must issue an app-only token and the second must fail.

Check invalid_client or federated-credential errors by comparing iss, sub, aud, tenant,
client ID, and token expiry. Keep external JWTs out of logs and artifacts.

See the [GitHub reference](../commands/Get-EntraIDTokenFromGitHubActions.md) and
[generic federation reference](../commands/Get-EntraIDTokenFromFederatedCredential.md).
