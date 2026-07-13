# Shared test fixtures for TokenTacticsV2 Pester tests

# A JWT token with fixed timestamps and known payload values.
# Header: { typ: "JWT", kid: "test-key-id", alg: "RS256" }
# Payload:
#   iss  = "https://sts.windows.net/00000000-0000-0000-0000-000000000001/"
#   aud  = "https://graph.microsoft.com"
#   oid  = "00000000-0000-0000-0000-000000000002"
#   name = "Test User"
#   tid  = "00000000-0000-0000-0000-000000000001"
#   nbf  = 1700000000  (2023-11-14T22:13:20Z)
#   exp  = 1700003600  (2023-11-14T23:13:20Z)
#   upn  = "test.user@contoso.com"
#   scp  = "User.Read"
#   iat  = 1700000000
# Signature is intentionally fake (JWT validation is not performed).
$script:TestJWT = "eyJ0eXAiOiJKV1QiLCJraWQiOiJ0ZXN0LWtleS1pZCIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEvIiwiYXVkIjoiaHR0cHM6Ly9ncmFwaC5taWNyb3NvZnQuY29tIiwib2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAyIiwibmFtZSI6IlRlc3QgVXNlciIsInRpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsIm5iZiI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwLCJ1cG4iOiJ0ZXN0LnVzZXJAY29udG9zby5jb20iLCJzY3AiOiJVc2VyLlJlYWQiLCJpYXQiOjE3MDAwMDAwMDB9.fakesignaturefortesting"

# A fake refresh token used when testing token-refresh functions
$script:FakeRefreshToken = "0.FakeRefreshToken.ForTesting"

# A fake access token (same as TestJWT for simplicity)
$script:FakeAccessToken = $script:TestJWT

# Module manifest path
$script:ModulePath = Join-Path $PSScriptRoot ".." ".." "TokenTactics.psd1"
