# Call a downstream API on behalf of a signed-in user

Use On-Behalf-Of when API A receives a user access token for API A and must call API
B with the same delegated user identity. The incoming token is not a Graph token
unless API A is Graph; its audience must be the middle-tier application.

## Architecture

    user client -> middle-tier API (aud=middle-tier) -> Entra token endpoint -> downstream API (delegated token)

The middle tier authenticates itself with either a client secret or a registered
certificate. The user assertion proves the delegated user context.

## Entra setup

1. Register the middle-tier API and expose its API scope.
2. Configure the client application to request that middle-tier scope.
3. Add downstream delegated permissions to the middle-tier app.
4. Grant consent for the downstream permissions.
5. Create a client secret or upload the middle-tier public certificate.
6. Ensure the incoming access token has aud equal to the middle-tier client ID or
   accepted application ID URI.

## Secret-backed exchange

    Get-EntraIDTokenOnBehalfOf -TenantId $tenantId -ClientId $middleTierId -ClientSecret $clientSecret -UserAssertion $incomingToken -Scope 'https://graph.microsoft.com/User.Read'

The command also accepts ClientSecretSecureString. For certificate authentication,
use CertificateThumbprint with the Windows store, or PfxPath with PfxPassword or
PfxPasswordSecureString.

## Verify the result

The downstream response should contain an access token with a delegated scp claim
and the signed-in user's identity. Send it only to the downstream resource named by
Scope. Never forward the middle-tier token to the downstream API.

## Failure tests

- Use a Graph token as UserAssertion while ClientId is the middle tier; local
  audience validation should reject it.
- Use an expired or altered assertion; Entra must reject it.
- Remove downstream consent; Entra should return a permission or consent error.
- Use a certificate not registered on the middle-tier app; Entra must reject it.

See the [OBO reference](../commands/Get-EntraIDTokenOnBehalfOf.md).
