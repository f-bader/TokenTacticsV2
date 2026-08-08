# OAuth and Workload Flow Validation Plan

Run all live checks in a disposable Entra tenant and against test app
registrations. Do not use production client secrets, user assertions, PFX files, or
Azure subscriptions.

## 1. Local regression gate

Run these checks on every supported OS before live validation:

    pwsh -NoProfile -Command 'Import-Module ./TokenTactics.psd1 -Force; Get-Command -Module TokenTactics'
    pwsh -NoProfile -Command 'Invoke-Pester ./tests/OAuthWorkloadFlows.Tests.ps1,./tests/Module.Tests.ps1 -Output Detailed'
    pwsh -NoProfile -Command 'Invoke-Pester ./tests -Output Normal'
    git diff --check

Expected result:

- Every new public command imports successfully.
- OAuthWorkloadFlows and module-contract Pester tests pass.
- The full suite is green on Windows. On the current macOS environment, the legacy
  Get-EntraIDTokenFromCertificate fixture cannot create a native self-signed
  certificate; record this as a pre-existing platform fixture issue if it recurs.
- No whitespace errors are reported.

Repeat the focused Pester suite on Windows, macOS, and Linux. On macOS/Linux, verify
that OpenSSL is installed for PFX fallback coverage:

    openssl version

## 2. Test tenant setup

Create separate disposable applications:

| Test app | Required configuration |
| --- | --- |
| Secret daemon | Microsoft Graph application permission, client secret, admin consent |
| Middle-tier API | Expose an API scope and add a redirect URI; record its client ID |
| Downstream API | Microsoft Graph delegated User.Read, or a disposable API with delegated scope |
| GitHub workload | Application permission, GitHub federated credential for one repo/environment |
| Generic federation | Application permission, Other issuer federated credential |
| Implicit test client | Web redirect URI and Access tokens enabled under Implicit grant and hybrid flows |
| Azure Arc identity | Arc-enabled test server with system-assigned identity and resource RBAC |

Use tenant IDs rather than common during token validation. Record client IDs, object
IDs, scope strings, issuer URLs, and redirect URIs in a local non-committed test
worksheet.

## 3. Client-secret flow

Run positive checks with plaintext and SecureString inputs:

    Get-EntraIDTokenFromClientSecret -TenantId <tenant> -ClientId <secret-app-id> -ClientSecret '<secret>' -Scope 'https://graph.microsoft.com/.default'
    $secret = Read-Host -AsSecureString
    Get-EntraIDTokenFromClientSecret -TenantId <tenant> -ClientId <secret-app-id> -ClientSecretSecureString $secret -Scope 'https://graph.microsoft.com/.default'

For each response, verify access_token exists, token_type is Bearer, and the decoded
token contains the test app ID in appid/azp and application roles appropriate to the
configured permissions. Confirm no refresh token is returned.

Negative cases:

- Bad secret returns an Entra invalid-client error and does not reveal the submitted secret.
- Expired secret returns an Entra invalid-client error.
- A delegated scope such as User.Read is rejected locally because client credentials
  require one .default resource scope.
- A multi-resource scope is rejected locally.

## 4. On-behalf-of flow

Acquire an access token for the middle-tier API by signing in as a dedicated test
user. Its aud claim must equal the middle-tier client ID or application ID URI
expected by the command.

    Get-EntraIDTokenOnBehalfOf -TenantId <tenant> -ClientId <middle-tier-id> -ClientSecret '<secret>' -UserAssertion <middle-tier-access-token> -Scope 'https://graph.microsoft.com/User.Read'

Repeat with a registered certificate/PFX. Verify the returned token has a delegated
scp claim, represents the test user, and is accepted by the downstream API.

Negative cases:

- Submit a Microsoft Graph token as the user assertion when the requester is the
  middle-tier API; local audience validation must reject it.
- Use a token from another tenant, an expired token, an invalid secret, and a
  certificate not registered on the middle-tier app; Entra must reject each request.
- Request an unconsented downstream scope and verify the expected consent/permission
  error.

## 5. Generic and GitHub federated credentials

For generic federation, configure an Other issuer credential whose issuer, subject,
and audience match an externally issued test JWT:

    Get-EntraIDTokenFromFederatedCredential -TenantId <tenant> -ClientId <federated-app-id> -FederatedToken <external-jwt> -Scope 'https://graph.microsoft.com/.default'

Repeat using FederatedTokenSecureString and FederatedTokenPath. Verify returned token
claims identify the Entra app, not the external workload identity.

For GitHub Actions, use a workflow with the exact repository/environment credential
and permissions: id-token: write:

    Get-EntraIDTokenFromGitHubActions -TenantId $env:AZURE_TENANT_ID -ClientId $env:AZURE_CLIENT_ID -Scope 'https://management.azure.com/.default'

Verify success on the configured branch/environment. Then run from a branch, tag,
pull request, repository, or environment not covered by the Entra subject rule and
verify Entra rejects the exchange.

## 6. Azure Arc managed identity

Run on a non-production Azure Arc-enabled Windows and Linux server with a
system-assigned identity:

    Get-EntraIDTokenFromAzureArcManagedIdentity -Resource 'https://management.azure.com/'

Verify the command detects IDENTITY_ENDPOINT, completes the challenge-file request,
returns an access token, and that the token can read only the test resource allowed
by its assigned RBAC role. Repeat with a Key Vault resource after assigning test-only
data-plane access.

Negative cases:

- Run outside an Arc machine and expect a clear missing-IDENTITY_ENDPOINT error.
- Replace IDENTITY_ENDPOINT with a non-loopback URL in a temporary shell and verify
  local validation rejects it.
- Remove the identity's RBAC role and verify the resource call, not token acquisition,
  is denied.

## 7. Implicit compatibility flow

With the implicit test client configured, run:

    $request = New-EntraIDImplicitAuthorizationUrl -TenantId <tenant> -ClientId <implicit-app-id> -RedirectUri '<registered-redirect-uri>' -Scope 'https://graph.microsoft.com/User.Read'
    Start-Process $request.AuthorizationUrl
    $token = ConvertFrom-EntraIDImplicitRedirect -RedirectUrl '<final-browser-url>' -ExpectedState $request.State

Verify the request URL contains response_type=token, response_mode=fragment, encoded
redirect URI, scope, and generated state. After sign-in, verify AccessToken, TokenType,
ExpiresIn, and Scope are populated.

Negative cases:

- Change ExpectedState and verify parser rejection.
- Paste a URL without a fragment and verify parser rejection.
- Disable implicit access tokens on the app registration and verify Entra returns the
  expected unsupported-response error.
- Test a non-registered redirect URI and verify Entra rejection.

## 8. Custom federated credential provider

Run the complete PFX workflow on Windows, macOS, and Linux:

    $password = Read-Host -AsSecureString
    New-TTFederatedSigningCertificate -PfxPath ./issuer.pfx -PfxPasswordSecureString $password -PublicCertificatePath ./issuer.cer
    New-TTFederatedIssuerMetadata -Issuer 'https://<stable-issuer-host>' -Subject 'test-workload' -OutputPath ./oidc-public -PfxPath ./issuer.pfx -PfxPasswordSecureString $password

Validate locally:

- oidc-public/.well-known/openid-configuration exists and issuer exactly matches the
  intended public HTTPS URL.
- The discovery document includes response_types_supported: ["id_token"],
  subject_types_supported: ["public"], and id_token_signing_alg_values_supported:
  ["RS256"]. Use Get-ChildItem -Force because .well-known is hidden.
- keys.json contains one RSA signing key, a kid, n, e, x5c, and RS256 algorithm.
- issuer-config.json contains no password or private-key material.
- The PFX is outside oidc-public.

Publish metadata through both supported options, independently:

1. Start the loopback static host, expose it through a Cloudflare named tunnel and
   stable custom hostname, then request both public URLs through HTTPS.
2. Deploy infra/oidc-static-website.bicep to a disposable resource group, upload
   oidc-public to the dollar-web container, and request both public URLs through the
   output static website URL.
   Confirm the deployment uses the Blob service API `2025-08-01` or later. A
   deployment that reports `InvalidRequestParameters` for
   `properties.staticWebsiteEnabled` is using an older API shape and must be
   retried with the checked-in template.

Create the Entra Other issuer federated credential with exact issuer, subject
test-workload, and audience api://AzureADTokenExchange. Then:

    $assertion = New-TTFederatedClientAssertion -Issuer 'https://<stable-issuer-host>' -Subject 'test-workload' -PfxPath ./issuer.pfx -PfxPasswordSecureString $password
    Get-EntraIDTokenFromFederatedCredential -TenantId <tenant> -ClientId <custom-federated-app-id> -FederatedToken $assertion -Scope 'https://graph.microsoft.com/.default'

Decode the assertion and verify iss, sub, aud, iat, nbf, exp, jti, and RS256 header.
Verify its signature using the JWK from keys.json. Verify Entra issues an application
token for the intended app.

Negative cases:

- Wrong issuer URL, subject, audience, signature, key, expired assertion, or altered
  JWKS must fail at Entra.
- Remove keys.json or discovery, wait for Entra metadata retrieval, and verify failure.
- Confirm the loopback host does not serve paths outside the metadata root and returns
  405 for non-GET/HEAD requests.
- Rotate the PFX: publish both old and new JWKs during overlap, update assertions to
  the new key, validate both during the overlap, then remove the old key only after
  all callers are migrated.

## 9. Acceptance criteria

The change is accepted when every local test passes, each live flow succeeds in the
test tenant with least-privilege permissions, all listed negative cases fail safely,
and no secrets, PFX files, challenge files, or assertions are committed or published
in metadata hosting.
